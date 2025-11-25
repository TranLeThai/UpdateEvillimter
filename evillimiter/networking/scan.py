import sys
import socket
import logging
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

from scapy.all import sr1, ARP, Ether, get_if_hwaddr  # Thêm Ether + get_if_hwaddr
from .host import Host
from evillimiter.console.io import IO

logger = logging.getLogger(__name__)

class HostScanner:
    def __init__(self, interface: str, iprange: List[str]):
        self.interface = interface
        self.iprange = iprange
        self.mac = get_if_hwaddr(interface)  # Lấy MAC attacker 1 lần duy nhất

        self.max_workers = 50
        self.retries = 0
        self.timeout = 1.5  # Nhanh hơn tí

    def scan(self, iprange: Optional[List[str]] = None) -> List[Host]:
        target_range = [str(x) for x in (self.iprange if iprange is None else iprange)]
        hosts = []

        logger.info(f"Scanning {len(target_range)} IPs...")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            try:
                results = list(tqdm(
                    executor.map(self._sweep, target_range),
                    total=len(target_range),
                    ncols=70,
                    bar_format='{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}',
                    leave=False
                ))

                for host in results:
                    if host:
                        self._resolve_name(host)
                        hosts.append(host)

            except KeyboardInterrupt:
                IO.ok('Scan aborted.')
                return hosts

        return hosts

    def scan_for_reconnects(self, hosts: List[Host], iprange: Optional[List[str]] = None) -> Dict[Host, Host]:
        target_range = [str(x) for x in (self.iprange if iprange is None else iprange)]

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            scanned_hosts = [h for h in executor.map(self._sweep, target_range) if h is not None]

        reconnected_hosts = {}
        for host in hosts:
            for s_host in scanned_hosts:
                if host.mac == s_host.mac and host.ip != s_host.ip:
                    s_host.name = host.name
                    reconnected_hosts[host] = s_host
        return reconnected_hosts

    def _sweep(self, ip: str) -> Optional[Host]:
        """Gửi ARP Request Layer 2 → KHÔNG WARNING"""
        try:
            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=ip, hwdst="00:00:00:00:00:00")
            answer, _ = sr1(packet, timeout=self.timeout, verbose=0, iface=self.interface, return_packets=True)
            if answer and answer[ARP].hwsrc:
                return Host(ip, answer[ARP].hwsrc, '')
        except Exception as e:
            logger.debug(f"ARP scan failed for {f}: {e}")
        return None

    def _resolve_name(self, host: Host) -> None:
        try:
            name = socket.gethostbyaddr(host.ip)[0]
            host.name = name.split('.')[0]  # Chỉ lấy tên ngắn
        except:
            host.name = ''