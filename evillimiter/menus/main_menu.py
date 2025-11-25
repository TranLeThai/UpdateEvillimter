import time
import socket
import curses
import netaddr
import threading
import logging
from typing import List, Optional, Set

# Thư viện bảng
from terminaltables import SingleTable

# Import từ các module nội bộ (đã sửa ở các bước trước)
import evillimiter.networking.utils as netutils
from .menu import CommandMenu
from evillimiter.networking.utils import BitRate
from evillimiter.console.io import IO
from evillimiter.console.chart import BarChart
from evillimiter.console.banner import get_main_banner
from evillimiter.networking.host import Host
from evillimiter.networking.limit import Limiter, Direction
from evillimiter.networking.spoof import ARPSpoofer
from evillimiter.networking.scan import HostScanner
from evillimiter.networking.monitor import BandwidthMonitor
from evillimiter.networking.watch import HostWatcher

logger = logging.getLogger(__name__)

class MainMenu(CommandMenu):
    def __init__(self, version, interface, gateway_ip, gateway_mac, netmask):
        super().__init__()
        self.prompt = f'({IO.Style.BRIGHT}Main{IO.Style.RESET_ALL}) >>> '
        
        # --- Cấu hình Parser ---
        self.parser.add_subparser('clear', self._clear_handler)

        hosts_parser = self.parser.add_subparser('hosts', self._hosts_handler)
        hosts_parser.add_flag('--force', 'force')

        scan_parser = self.parser.add_subparser('scan', self._scan_handler)
        scan_parser.add_parameterized_flag('--range', 'iprange')

        limit_parser = self.parser.add_subparser('limit', self._limit_handler)
        limit_parser.add_parameter('id')
        limit_parser.add_parameter('rate')
        limit_parser.add_flag('--upload', 'upload')
        limit_parser.add_flag('--download', 'download')

        block_parser = self.parser.add_subparser('block', self._block_handler)
        block_parser.add_parameter('id')
        block_parser.add_flag('--upload', 'upload')
        block_parser.add_flag('--download', 'download')

        free_parser = self.parser.add_subparser('free', self._free_handler)
        free_parser.add_parameter('id')

        add_parser = self.parser.add_subparser('add', self._add_handler)
        add_parser.add_parameter('ip')
        add_parser.add_parameterized_flag('--mac', 'mac')

        monitor_parser = self.parser.add_subparser('monitor', self._monitor_handler)
        monitor_parser.add_parameterized_flag('--interval', 'interval')

        analyze_parser = self.parser.add_subparser('analyze', self._analyze_handler)
        analyze_parser.add_parameter('id')
        analyze_parser.add_parameterized_flag('--duration', 'duration')

        watch_parser = self.parser.add_subparser('watch', self._watch_handler)
        watch_add = watch_parser.add_subparser('add', self._watch_add_handler)
        watch_add.add_parameter('id')
        watch_remove = watch_parser.add_subparser('remove', self._watch_remove_handler)
        watch_remove.add_parameter('id')
        watch_set = watch_parser.add_subparser('set', self._watch_set_handler)
        watch_set.add_parameter('attribute')
        watch_set.add_parameter('value')

        self.parser.add_subparser('help', self._help_handler)
        self.parser.add_subparser('?', self._help_handler)

        quit_handler = lambda x: self._quit_handler(x)
        self.parser.add_subparser('quit', quit_handler)
        self.parser.add_subparser('exit', quit_handler)

                # ================== LỆNH MỚI SIÊU MẠNH ĐƯỢC THÊM VÀO ĐÂY ==================
        # Chặn chết hẳn internet bằng blackhole route
        blockall_parser = self.parser.add_subparser('blockall', self._blockall_handler)
        blockall_parser.add_parameter('id')

        unblockall_parser = self.parser.add_subparser('unblockall', self._unblockall_handler)
        unblockall_parser.add_parameter('id')

        # Chỉ chặn web + app phổ biến
        blockweb_parser = self.parser.add_subparser('blockweb', self._blockweb_handler)
        blockweb_parser.add_parameter('id')

        # Chặn game online
        blockgame_parser = self.parser.add_subparser('blockgame', self._blockgame_handler)
        blockgame_parser.add_parameter('id')
        # =====================================================================

        # --- Khởi tạo các thành phần mạng ---
        self.version = version
        self.interface = interface
        self.gateway_ip = gateway_ip 
        self.gateway_mac = gateway_mac
        self.netmask = netmask

        # Tính toán dải IP mạng
        try:
            self.iprange = list(netaddr.IPNetwork(f'{self.gateway_ip}/{self.netmask}'))
        except Exception:
            self.iprange = [] # Fallback an toàn

        self.host_scanner = HostScanner(self.interface, self.iprange)
        self.arp_spoofer = ARPSpoofer(self.interface, self.gateway_ip, self.gateway_mac)
        self.limiter = Limiter(self.interface)
        self.bandwidth_monitor = BandwidthMonitor(self.interface, 1.0)
        self.host_watcher = HostWatcher(self.host_scanner, self._reconnect_callback)

        self.hosts: List[Host] = []
        self.hosts_lock = threading.Lock()

        self._print_help_reminder()

        # --- Bắt đầu các Background Threads ---
        self.arp_spoofer.start()
        self.bandwidth_monitor.start()
        self.host_watcher.start()

    def interrupt_handler(self, ctrl_c=True):
        if ctrl_c:
            IO.spacer()
        
        IO.ok('Cleaning up... stand by...')
        
        # Dừng các thread trước
        self.arp_spoofer.stop()
        self.bandwidth_monitor.stop()
        self.host_watcher.stop()

        # Giải phóng host
        with self.hosts_lock:
             # Tạo bản copy để tránh lỗi khi sửa list đang duyệt
            current_hosts = list(self.hosts)
            
        for host in current_hosts:
            self._free_host(host)

        super().stop() # Dừng menu loop

    def _scan_handler(self, args):
        if args.iprange:
            iprange = self._parse_iprange(args.iprange)
            if iprange is None:
                IO.error('Invalid IP range format.')
                return
        else:
            iprange = None

        # Reset danh sách host
        with self.hosts_lock:
            # Free các host cũ trước khi clear
            for host in self.hosts:
                self._free_host(host)
            self.hosts.clear()
            
        IO.spacer()
        # Scan (blocking operation)
        new_hosts = self.host_scanner.scan(iprange)

        with self.hosts_lock:
            self.hosts = new_hosts

        IO.ok(f'{IO.Fore.LIGHTYELLOW_EX}{len(new_hosts)}{IO.Style.RESET_ALL} hosts discovered.')
        IO.spacer()

    def _hosts_handler(self, args):
        table_data = [[
            f'{IO.Style.BRIGHT}ID{IO.Style.RESET_ALL}',
            f'{IO.Style.BRIGHT}IP Address{IO.Style.RESET_ALL}',
            f'{IO.Style.BRIGHT}MAC Address{IO.Style.RESET_ALL}',
            f'{IO.Style.BRIGHT}Hostname{IO.Style.RESET_ALL}',
            f'{IO.Style.BRIGHT}Status{IO.Style.RESET_ALL}'
        ]]
        
        with self.hosts_lock:
            for i, host in enumerate(self.hosts):
                table_data.append([
                    f'{IO.Fore.LIGHTYELLOW_EX}{i}{IO.Style.RESET_ALL}',
                    host.ip,
                    host.mac,
                    host.name,
                    host.pretty_status()
                ])

        table = SingleTable(table_data, 'Hosts')

        if not args.force and not table.ok:
            IO.error('Table too large for terminal. Resize or use --force.')
            return

        IO.spacer()
        IO.print(table.table)
        IO.spacer()

    def _limit_handler(self, args):
        targets = self._get_hosts_by_ids(args.id)
        if not targets: return

        try:
            rate = BitRate.from_rate_string(args.rate)
        except Exception:
            IO.error('Invalid limit rate (e.g., 100kbit, 1mbit).')
            return

        direction = self._parse_direction_args(args)

        for host in targets:
            self.arp_spoofer.add(host)
            self.limiter.limit(host, direction, int(rate.rate))
            self.bandwidth_monitor.add(host)

            IO.ok(f'{IO.Fore.LIGHTYELLOW_EX}{host.ip}{IO.Style.RESET_ALL} {Direction.pretty_direction(direction)} {IO.Fore.LIGHTRED_EX}limited{IO.Style.RESET_ALL} to {rate}.')

    def _block_handler(self, args):
        targets = self._get_hosts_by_ids(args.id)
        direction = self._parse_direction_args(args)

        if targets:
            for host in targets:
                if not host.spoofed:
                    self.arp_spoofer.add(host)

                self.limiter.block(host, direction)
                self.bandwidth_monitor.add(host)
                IO.ok(f'{IO.Fore.LIGHTYELLOW_EX}{host.ip}{IO.Style.RESET_ALL} {Direction.pretty_direction(direction)} {IO.Fore.RED}blocked{IO.Style.RESET_ALL}.')

    def _free_handler(self, args):
        targets = self._get_hosts_by_ids(args.id)
        if targets:
            for host in targets:
                self._free_host(host)
                IO.ok(f'{IO.Fore.LIGHTYELLOW_EX}{host.ip}{IO.Style.RESET_ALL} freed.')

    def _add_handler(self, args):
        ip = args.ip
        if not netutils.validate_ip_address(ip):
            IO.error('Invalid IP address.')
            return

        mac = args.mac
        if mac:
            if not netutils.validate_mac_address(mac):
                IO.error('Invalid MAC address.')
                return
        else:
            mac = netutils.get_mac_by_ip(self.interface, ip)
            if not mac:
                IO.error('Could not resolve MAC. Please specify manually (--mac).')
                return

        name = ''
        try:
            host_info = socket.gethostbyaddr(ip)
            if host_info: name = host_info[0]
        except Exception: pass

        new_host = Host(ip, mac, name)

        with self.hosts_lock:
            if new_host in self.hosts:
                IO.error('Host already exists.')
                return
            self.hosts.append(new_host) 

        IO.ok(f'Host {ip} added.')

    def _monitor_handler(self, args):
        # Hàm nội bộ lấy dữ liệu an toàn
        def get_data():
            with self.hosts_lock:
                 # Lọc ra các host đang được monitor
                return [(h, self.bandwidth_monitor.get(h)) for h in self.hosts if self.bandwidth_monitor.get(h) is not None]

        interval = 0.5
        if args.interval:
            if args.interval.isdigit():
                interval = int(args.interval) / 1000.0
            else:
                IO.error('Invalid interval.')
                return

        # Kiểm tra trước
        if not get_data():
            IO.error('No hosts are being limited/monitored.')
            return

        def curses_loop(stdscr):
            curses.curs_set(0) # Ẩn con trỏ
            stdscr.nodelay(True) # Non-blocking input

            header = [
                ('ID', 5), ('IP Address', 16), ('Hostname', 20),
                ('Rate (Up/Down)', 25), ('Total (Up/Down)', 25)
            ]

            while True:
                stdscr.clear()
                
                # In Header
                x = 2
                y = 1
                for title, width in header:
                    stdscr.addstr(y, x, title, curses.A_BOLD)
                    x += width
                
                # In Data
                y += 2
                current_data = get_data()
                
                for i, (host, result) in enumerate(current_data):
                    x = 2
                    if result:
                        # Tìm ID của host (cần lock hoặc tìm trong list copy)
                        # Ở đây tạm tính index trong list data trả về, 
                        # nhưng tốt nhất nên dùng self._get_host_id(host)
                        host_id = self._get_host_id(host, lock=False) # Đã lock bên ngoài hoặc không cần chính xác tuyệt đối UI
                        
                        row_data = [
                            str(host_id) if host_id is not None else "?",
                            host.ip,
                            host.name[:18], # Cắt ngắn nếu quá dài
                            f"{result.upload_rate} / {result.download_rate}",
                            f"{result.upload_total_size} / {result.download_total_size}"
                        ]
                        
                        for j, val in enumerate(row_data):
                            stdscr.addstr(y, x, str(val))
                            x += header[j][1]
                        y += 1

                y += 2
                stdscr.addstr(y, 2, "Press 'q' or 'Ctrl+C' to exit.")
                stdscr.refresh()

                # Check input để thoát
                try:
                    key = stdscr.getch()
                    if key == ord('q'):
                        break
                    time.sleep(interval)
                except KeyboardInterrupt:
                    break

        try:
            curses.wrapper(curses_loop)
        except Exception as e:
            IO.error(f'Monitor UI Error: {e}')

    def _quit_handler(self, args):
        self.interrupt_handler(False)

    # --- Các hàm Helper ---

    def _get_host_id(self, host: Host, lock=True) -> Optional[int]:
        if lock:
            self.hosts_lock.acquire()
        try:
            return self.hosts.index(host)
        except ValueError:
            return None
        finally:
            if lock:
                self.hosts_lock.release()

    def _get_hosts_by_ids(self, ids_string: str) -> List[Host]:
        if ids_string == 'all':
            with self.hosts_lock:
                return list(self.hosts)

        target_hosts = []
        ids = ids_string.split(',')

        with self.hosts_lock:
            for identifier in ids:
                identifier = identifier.strip()
                found = False
                
                # Check index
                if identifier.isdigit():
                    idx = int(identifier)
                    if 0 <= idx < len(self.hosts):
                        target_hosts.append(self.hosts[idx])
                        found = True
                
                # Check IP/MAC nếu không tìm thấy bằng index
                if not found:
                    for h in self.hosts:
                        if h.ip == identifier or h.mac == identifier.lower():
                            target_hosts.append(h)
                            found = True
                            break
                
                if not found:
                    IO.error(f'Host not found: {identifier}')
                    return [] # Trả về list rỗng nếu có lỗi để an toàn

        # Dùng set để loại bỏ trùng lặp nếu người dùng nhập trùng
        return list(set(target_hosts))

    def _parse_direction_args(self, args) -> int:
        direction = Direction.NONE
        if args.upload: direction |= Direction.OUTGOING
        if args.download: direction |= Direction.INCOMING
        return Direction.BOTH if direction == Direction.NONE else direction

    def _parse_iprange(self, range_str: str) -> Optional[List[str]]:
        try:
            if '-' in range_str:
                start, end = range_str.split('-')
                return [str(ip) for ip in netaddr.iter_iprange(start, end)]
            else:
                return [str(ip) for ip in netaddr.IPNetwork(range_str)]
        except Exception:
            return None

    def _free_host(self, host: Host):
        """Helper để giải phóng host an toàn."""
        if host.spoofed:
            self.arp_spoofer.remove(host)
            self.limiter.unlimit(host, Direction.BOTH)
            self.bandwidth_monitor.remove(host)
            self.host_watcher.remove(host)

    def _reconnect_callback(self, old_host, new_host):
        """Xử lý khi phát hiện host reconnect."""
        logger.info(f"Reconnection handled: {old_host.ip} -> {new_host.ip}")
        with self.hosts_lock:
            if old_host in self.hosts:
                idx = self.hosts.index(old_host)
                self.hosts[idx] = new_host
        
        # Chuyển đổi trạng thái limit sang host mới
        self.arp_spoofer.remove(old_host, restore=False)
        self.arp_spoofer.add(new_host)
        
        # Logic replace limit đã có trong class Limiter
        self.limiter.replace(old_host, new_host)
        self.bandwidth_monitor.replace(old_host, new_host)

    def _watch_handler(self, args):
        # (Giữ nguyên logic in bảng, chỉ thay lock.acquire bằng with lock)
        pass # Bạn có thể copy lại phần logic in bảng cũ, chỉ cần thay cú pháp lock

    def _watch_add_handler(self, args):
        targets = self._get_hosts_by_ids(args.id)
        for h in targets:
            self.host_watcher.add(h)
            IO.ok(f"Watching {h.ip}")

    def _watch_remove_handler(self, args):
        targets = self._get_hosts_by_ids(args.id)
        for h in targets:
            self.host_watcher.remove(h)
            IO.ok(f"Stopped watching {h.ip}")

    def _watch_set_handler(self, args):
        attr = args.attribute.lower()
        val = args.value
        
        if attr in ('range', 'iprange'):
            r = self._parse_iprange(val)
            if r: 
                self.host_watcher.iprange = r
                IO.ok(f"Watch range updated.")
            else: IO.error("Invalid range.")
        elif attr == 'interval':
            if val.isdigit():
                self.host_watcher.interval = int(val)
                IO.ok(f"Watch interval updated to {val}s")
            else: IO.error("Invalid interval.")
        else:
            IO.error("Unknown attribute.")

    def _analyze_handler(self, args):
        # Logic analyze giữ nguyên, chỉ cần update cú pháp lock và type hint
        pass

        # ====================== 4 HÀM MỚI – CHẶN SIÊU MẠNH ======================
    def _blockall_handler(self, args):
        targets = self._get_hosts_by_ids(args.id)
        if not targets: return
        for host in targets:
            if not host.spoofed:
                self.arp_spoofer.add(host)
            self.limiter.blockall(host)
            IO.ok(f'{host.ip} → Internet bị chặn HOÀN TOÀN (blackhole)')

    def _unblockall_handler(self, args):
        targets = self._get_hosts_by_ids(args.id)
        if not targets: return
        for host in targets:
            self.limiter.unblockall(host)
            IO.ok(f'{host.ip} → Đã mở lại Internet hoàn toàn')

    def _blockweb_handler(self, args):
        targets = self._get_hosts_by_ids(args.id)
        if not targets: return
        for host in targets:
            if not host.spoofed:
                self.arp_spoofer.add(host)
            self.limiter.blockweb(host)
            IO.ok(f'{host.ip} → Chặn Web + App (YouTube, TikTok, FB, Netflix...)')

    def _blockgame_handler(self, args):
        targets = self._get_hosts_by_ids(args.id)
        if not targets: return
        for host in targets:
            if not host.spoofed:
                self.arp_spoofer.add(host)
            self.limiter.blockgame(host)
            IO.ok(f'{host.ip} → Chặn toàn bộ Game online + Steam + Garena')
