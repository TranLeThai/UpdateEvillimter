import sys
import evillimiter.console.shell as shell

# Constants
BROADCAST: str = 'ff:ff:ff:ff:ff:ff'
IP_FORWARD_LOC: str = 'net.ipv4.ip_forward'

def _require_binary(name: str) -> str:
    """
    Tìm đường dẫn file thực thi. 
    Nếu không tìm thấy, dừng chương trình và báo lỗi hướng dẫn cài đặt.
    """
    path = shell.locate_bin(name)
    if not path:
        # In trực tiếp ra stderr vì Logger có thể chưa khởi tạo ở giai đoạn này
        print(f"\n[!] Critical Error: Required binary '{name}' not found.", file=sys.stderr)
        print(f"    Please install '{name}' (usually part of iproute2/iptables package) to continue.\n", file=sys.stderr)
        sys.exit(1)
    return path

# Tự động kiểm tra và gán đường dẫn binary
# Nếu máy thiếu các công cụ này, chương trình sẽ dừng ngay tại dòng import này
BIN_TC: str = _require_binary('tc')
BIN_IPTABLES: str = _require_binary('iptables')
BIN_SYSCTL: str = _require_binary('sysctl')