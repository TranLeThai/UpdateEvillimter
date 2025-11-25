import threading
import logging
from typing import Tuple, Optional

import evillimiter.console.shell as shell
from .host import Host
from evillimiter.common.globals import BIN_TC, BIN_IPTABLES

logger = logging.getLogger(__name__)

class Direction:
    NONE = 0
    OUTGOING = 1
    INCOMING = 2
    BOTH = 3

    @staticmethod
    def pretty_direction(direction: int) -> str:
        if direction == Direction.OUTGOING: return 'upload'
        if direction == Direction.INCOMING: return 'download'
        if direction == Direction.BOTH: return 'upload / download'
        return '-'

class Limiter:
    class HostLimitIDs:
        def __init__(self, upload_id: int, download_id: int):
            self.upload_id = upload_id
            self.download_id = download_id

            # chỗ này

    def __init__(self, interface: str):
        self.interface = interface
        self._host_dict = {}
        self._host_dict_lock = threading.Lock()

    def limit(self, host: Host, direction: int, rate: int) -> None:
        """Giới hạn băng thông host."""
        host_ids = self._get_or_create_ids(host, direction)

        # Rate burst calculation (10% overhead for burst usually good)
        burst = int(rate * 1.1)

        if direction & Direction.OUTGOING:
            # TC class & filter for Upload
            shell.execute_suppressed(f'{BIN_TC} class add dev {self.interface} parent 1:0 classid 1:{host_ids.upload_id} htb rate {rate}bit burst {burst}bit')
            shell.execute_suppressed(f'{BIN_TC} filter add dev {self.interface} parent 1:0 protocol ip prio {host_ids.upload_id} handle {host_ids.upload_id} fw flowid 1:{host_ids.upload_id}')
            # IPtables Mark
            shell.execute_suppressed(f'{BIN_IPTABLES} -t mangle -A POSTROUTING -s {host.ip} -j MARK --set-mark {host_ids.upload_id}')

        if direction & Direction.INCOMING:
            # TC class & filter for Download
            shell.execute_suppressed(f'{BIN_TC} class add dev {self.interface} parent 1:0 classid 1:{host_ids.download_id} htb rate {rate}bit burst {burst}bit')
            shell.execute_suppressed(f'{BIN_TC} filter add dev {self.interface} parent 1:0 protocol ip prio {host_ids.download_id} handle {host_ids.download_id} fw flowid 1:{host_ids.download_id}')
            # IPtables Mark
            shell.execute_suppressed(f'{BIN_IPTABLES} -t mangle -A PREROUTING -d {host.ip} -j MARK --set-mark {host_ids.download_id}')

        host.limited = True
        logger.info(f"Limited {host.ip} ({Direction.pretty_direction(direction)}) to {rate}bit")

        with self._host_dict_lock:
            self._host_dict[host] = {'ids': host_ids, 'rate': rate, 'direction': direction}

    def block(self, host: Host, direction: int) -> None:
        """Chặn hoàn toàn host."""
        host_ids = self._get_or_create_ids(host, direction)

        if direction & Direction.OUTGOING:
            shell.execute_suppressed(f'{BIN_IPTABLES} -t filter -A FORWARD -s {host.ip} -j DROP')
        if direction & Direction.INCOMING:
            shell.execute_suppressed(f'{BIN_IPTABLES} -t filter -A FORWARD -d {host.ip} -j DROP')

        host.blocked = True
        logger.info(f"Blocked {host.ip} ({Direction.pretty_direction(direction)})")

        with self._host_dict_lock:
            self._host_dict[host] = {'ids': host_ids, 'rate': None, 'direction': direction}

    def unlimit(self, host: Host, direction: int) -> None:
        if not host.limited and not host.blocked:
            return

        with self._host_dict_lock:
            if host not in self._host_dict:
                return
            host_ids = self._host_dict[host]['ids']

            if direction & Direction.OUTGOING:
                self._delete_tc_class(host_ids.upload_id)
                self._delete_iptables_entries(host, Direction.OUTGOING, host_ids.upload_id)
            if direction & Direction.INCOMING:
                self._delete_tc_class(host_ids.download_id)
                self._delete_iptables_entries(host, Direction.INCOMING, host_ids.download_id)
            
            # Remove from dict if we are unlimiting everything
            # (Simplification: assuming unlimit usually clears the host)
            del self._host_dict[host]

        host.limited = False
        host.blocked = False
        logger.info(f"Unlimited {host.ip}")

    def replace(self, old_host: Host, new_host: Host) -> None:
        with self._host_dict_lock:
            info = self._host_dict.get(old_host)

        if info:
            # Remove old restrictions
            self.unlimit(old_host, Direction.BOTH)
            
            # Apply to new host
            if info['rate'] is None:
                self.block(new_host, info['direction'])
            else:
                self.limit(new_host, info['direction'], info['rate'])

    def _get_or_create_ids(self, host: Host, direction: int):
        with self._host_dict_lock:
            present = host in self._host_dict
        
        if present:
            # If already present, unlimit first to clear old rules before re-applying
            self.unlimit(host, direction)
            # Fetch again after unlimit (logic might need adjustment if unlimit deletes key)
            # For safety, just create new IDs or reuse logic.
        
        return self.HostLimitIDs(*self._create_ids())

    def _create_ids(self) -> Tuple[int, int]:
        """Generates 2 unique IDs."""
        id_gen = 1
        with self._host_dict_lock:
            # Collect all used IDs
            used_ids = set()
            for info in self._host_dict.values():
                ids = info['ids']
                used_ids.add(ids.upload_id)
                used_ids.add(ids.download_id)
            
            # Find 2 free slots
            results = []
            while len(results) < 2:
                if id_gen not in used_ids:
                    results.append(id_gen)
                id_gen += 1
            return (results[0], results[1])

    def _delete_tc_class(self, id_: int) -> None:
        shell.execute_suppressed(f'{BIN_TC} filter del dev {self.interface} parent 1:0 prio {id_}')
        shell.execute_suppressed(f'{BIN_TC} class del dev {self.interface} parent 1:0 classid 1:{id_}')

    def _delete_iptables_entries(self, host: Host, direction: int, id_: int) -> None:
        if direction & Direction.OUTGOING:
            shell.execute_suppressed(f'{BIN_IPTABLES} -t mangle -D POSTROUTING -s {host.ip} -j MARK --set-mark {id_}')
            shell.execute_suppressed(f'{BIN_IPTABLES} -t filter -D FORWARD -s {host.ip} -j DROP')
        if direction & Direction.INCOMING:
            shell.execute_suppressed(f'{BIN_IPTABLES} -t mangle -D PREROUTING -d {host.ip} -j MARK --set-mark {id_}')
            shell.execute_suppressed(f'{BIN_IPTABLES} -t filter -D FORWARD -d {host.ip} -j DROP')

        # ====================== 4 HÀM CHẶN SIÊU MẠNH - ĐÃ FIX 100% ======================
    def blockall(self, host: Host) -> None:
        """Chặn chết internet hoàn toàn bằng blackhole route – mạnh nhất, không bypass được"""
        try:
            shell.execute_suppressed(f'ip route add blackhole {host.ip}', root=True)
            host.blocked = True
            logger.info(f"[BLOCKALL] {host.ip} → Internet bị chặn chết (blackhole)")
        except Exception as e:
            logger.error(f"blockall failed for {host.ip}: {e}")

    def unblockall(self, host: Host) -> None:
        """Mở lại hoàn toàn sau blockall"""
        try:
            shell.execute_suppressed(f'ip route del blackhole {host.ip}', root=True)
            host.blocked = False
            logger.info(f"[UNBLOCKALL] {host.ip} → Đã mở lại Internet")
        except:
            pass  # Nếu route không tồn tại thì bỏ qua, an toàn

    def blockweb(self, host: Host) -> None:
        """Chặn Web + App phổ biến: YouTube, TikTok, FB, Instagram, Netflix, Zalo, Discord..."""
        cmds = [
            f'{BIN_IPTABLES} -I FORWARD -s {host.ip} -p tcp --dport 80 -j DROP',
            f'{BIN_IPTABLES} -I FORWARD -s {host.ip} -p tcp --dport 443 -j DROP',
            f'{BIN_IPTABLES} -I FORWARD -s {host.ip} -p udp --dport 443 -j DROP',  # QUIC / HTTP3
            f'{BIN_IPTABLES} -I FORWARD -s {host.ip} -p tcp --dport 53 -j DROP',   # DNS TCP
            f'{BIN_IPTABLES} -I FORWARD -s {host.ip} -p udp --dport 53 -j DROP',   # DNS UDP
            # Bonus: chặn DNS nổi tiếng để tránh bypass
            f'{BIN_IPTABLES} -I FORWARD -s {host.ip} -d 8.8.8.8 -j DROP',
            f'{BIN_IPTABLES} -I FORWARD -s {host.ip} -d 1.1.1.1 -j DROP',
        ]
        for cmd in cmds:
            shell.execute_suppressed(cmd, root=True)
        host.blocked = True
        logger.info(f"[BLOCKWEB] {host.ip} → Đã chặn Web + App")

    def blockgame(self, host: Host) -> None:
        """Chặn toàn bộ Game online phổ biến VN + Steam + Valorant + Liên Minh + FreeFire + PUBG"""
        game_ports = [
            # Steam
            27015,27016,27017,27018,27019,27020,27030,27031,27036,27037,
            # Garena / Liên Minh / FreeFire / FIFA Online
            10001,10009,10010,10012,10070,10101,10999,11000,15101,15103,
            # Valorant / Riot
            5222,5223,8080,8393,8400,7000,8000,9000,
            # PUBG / Apex / Call of Duty
            20000,20001,20002,10010,10012,
            # Minecraft, Roblox, Genshin Impact
            25565,19132,22115,22116,
            # Backup: chặn HTTPS + HTTP (nhiều game dùng)
            80, 443
        ]
        cmds = []
        for port in game_ports:
            cmds.append(f'{BIN_IPTABLES} -I FORWARD -s {host.ip} -p tcp --dport {port} -j DROP')
            cmds.append(f'{BIN_IPTABLES} -I FORWARD -s {host.ip} -p udp --dport {port} -j DROP')
        for cmd in cmds:
            shell.execute_suppressed(cmd, root=True)
        host.blocked = True
        logger.info(f"[BLOCKGAME] {host.ip} → Đã chặn toàn bộ Game online")
    # ============================================================================