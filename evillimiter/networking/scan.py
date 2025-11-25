import sys
import socket
import logging
from typing import List, Optional, Dict
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

from scapy.all import sr1, ARP  # pylint: disable=no-name-in-module
from .host import Host
from evillimiter.console.io import IO

logger = logging.getLogger(__name__)

class HostScanner:
    def __init__(self, interface: str, iprange: List[str]):
        self.interface = interface
        self.iprange = iprange

        self.max_workers = 50   # Adjusted slightly safe number
        self.retries = 0        
        self.timeout = 2.0      # Slightly lower timeout for speed

    def scan(self, iprange: Optional[List[str]] = None) -> List[Host]:
        target_range = [str(x) for x in (self.iprange if iprange is None else iprange)]
        hosts = []

        logger.info(f"Scanning {len(target_range)} IPs...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Use tqdm for progress bar
            try:
                results = list(tqdm(
                    executor.map(self._sweep, target_range),
                    total=len(target_range),
                    ncols=60,
                    bar_format='{percentage:3.0f}% |{bar}| {n_fmt}/{total_fmt}',
                    leave=False
                ))
                
                # Filter None results and resolve names
                for host in results:
                    if host:
                        self._resolve_name(host)
                        hosts.append(host)
                        
            except KeyboardInterrupt:
                IO.ok('Scan aborted.')
                return hosts # Return what we found so far

        return hosts

    def scan_for_reconnects(self, hosts: List[Host], iprange: Optional[List[str]] = None) -> Dict[Host, Host]:
        target_range = [str(x) for x in (self.iprange if iprange is None else iprange)]
        
        # Quick scan without UI
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            scanned_hosts = [h for h in executor.map(self._sweep, target_range) if h is not None]

        reconnected_hosts = {}
        # Check if MAC matches but IP changed
        for host in hosts:
            for s_host in scanned_hosts:
                if host.mac == s_host.mac and host.ip != s_host.ip:
                    s_host.name = host.name # Preserve name
                    reconnected_hosts[host] = s_host
        
        return reconnected_hosts

    def _sweep(self, ip: str) -> Optional[Host]:
        """Gửi ARP Request để kiểm tra Host Online."""
        try:
            packet = ARP(op=1, pdst=ip)
            answer = sr1(packet, retry=self.retries, timeout=self.timeout, verbose=0, iface=self.interface)
            if answer:
                return Host(ip, answer.hwsrc, '')
        except Exception:
            pass
        return None

    def _resolve_name(self, host: Host) -> None:
        try:
            host_info = socket.gethostbyaddr(host.ip)
            host.name = host_info[0] if host_info else ''
        except socket.herror:
            host.name = ''