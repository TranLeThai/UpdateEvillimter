import time
import threading
import logging
from dataclasses import dataclass
from typing import Dict, Optional
from scapy.all import sniff, IP  # pylint: disable=no-name-in-module

from .utils import ValueConverter, BitRate, ByteValue
from .host import Host

logger = logging.getLogger(__name__)

@dataclass
class MonitorResult:
    upload_rate: BitRate = BitRate(0)
    upload_total_size: ByteValue = ByteValue(0)
    upload_total_count: int = 0
    download_rate: BitRate = BitRate(0)
    download_total_size: ByteValue = ByteValue(0)
    download_total_count: int = 0
    
    # Internal temp counters
    _upload_temp_size: ByteValue = ByteValue(0)
    _download_temp_size: ByteValue = ByteValue(0)

class BandwidthMonitor:
    def __init__(self, interface: str, interval: float = 1.0):
        self.interface = interface
        self.interval = interval # Unused directly but good for reference

        self._host_result_dict: Dict[Host, Dict] = {}
        self._host_result_lock = threading.Lock()

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def add(self, host: Host) -> None:
        with self._host_result_lock:
            if host not in self._host_result_dict:
                self._host_result_dict[host] = {
                    'result': MonitorResult(),
                    'last_now': time.time()
                }
                logger.debug(f"Monitor added host: {host.ip}")

    def remove(self, host: Host) -> None:
        with self._host_result_lock:
            if self._host_result_dict.pop(host, None):
                logger.debug(f"Monitor removed host: {host.ip}")

    def replace(self, old_host: Host, new_host: Host) -> None:
        with self._host_result_lock:
            if old_host in self._host_result_dict:
                self._host_result_dict[new_host] = self._host_result_dict[old_host]
                del self._host_result_dict[old_host]

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff, daemon=True, name="BandwidthMonitorThread")
        self._thread.start()
        logger.info("Bandwidth Monitor started.")

    def stop(self) -> None:
        self._stop_event.set()
        # Sniffing thread might take a moment to stop due to blocking socket
        if self._thread:
             # Don't join with long timeout as sniff can be slow to exit
            pass 
        logger.info("Bandwidth Monitor stopped.")

    def get(self, host: Host) -> Optional[MonitorResult]:
        with self._host_result_lock:
            if host in self._host_result_dict:
                data = self._host_result_dict[host]
                last_now = data['last_now']
                result: MonitorResult = data['result']
                
                now = time.time()
                time_passed = now - last_now
                
                if time_passed > 0:
                    # Calculate rates
                    up_bits = ValueConverter.byte_to_bit(result._upload_temp_size.value)
                    down_bits = ValueConverter.byte_to_bit(result._download_temp_size.value)
                    
                    result.upload_rate = BitRate(int(up_bits / time_passed))
                    result.download_rate = BitRate(int(down_bits / time_passed))

                # Reset temp counters
                result._upload_temp_size = ByteValue(0)
                result._download_temp_size = ByteValue(0)

                data['last_now'] = now
                return result
        return None

    def _sniff(self) -> None:
        def pkt_handler(pkt):
            if not pkt.haslayer(IP):
                return
                
            with self._host_result_lock:
                # Iterate safely over keys
                for host, data in self._host_result_dict.items():
                    result = data['result']
                    pkt_len = len(pkt)
                    
                    if host.ip == pkt[IP].src:
                        result.upload_total_size += pkt_len
                        result.upload_total_count += 1
                        result._upload_temp_size += pkt_len
                    elif host.ip == pkt[IP].dst:
                        result.download_total_size += pkt_len
                        result.download_total_count += 1
                        result._download_temp_size += pkt_len
                        
        def stop_filter(pkt):
            return self._stop_event.is_set()

        try:
            sniff(iface=self.interface, prn=pkt_handler, stop_filter=stop_filter, store=0)
        except Exception as e:
            logger.error(f"Sniffing error: {e}")