import subprocess
import logging
from typing import Optional

# Không import IO ở đây để tránh Circular Dependency (shell <-> io)

logger = logging.getLogger(__name__)

def execute(command: str, root: bool = True) -> int:
    """Thực thi lệnh và trả về exit code."""
    cmd = f"sudo {command}" if root else command
    try:
        return subprocess.run(cmd, shell=True, check=False).returncode
    except Exception as e:
        logger.error(f"Execution error: {e}")
        return 1

def execute_suppressed(command: str, root: bool = True) -> int:
    """Thực thi lệnh nhưng ẩn toàn bộ output."""
    cmd = f"sudo {command}" if root else command
    try:
        return subprocess.run(
            cmd, 
            shell=True, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        ).returncode
    except Exception as e:
        logger.error(f"Suppressed execution error: {e}")
        return 1

def output(command: str, root: bool = True) -> str:
    """Thực thi và lấy output (stdout)."""
    cmd = f"sudo {command}" if root else command
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            check=True, 
            stdout=subprocess.PIPE
        )
        return result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}, {e}")
        return ""

def output_suppressed(command: str, root: bool = True) -> str:
    """Thực thi và lấy output, bỏ qua stderr."""
    cmd = f"sudo {command}" if root else command
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            check=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.DEVNULL
        )
        return result.stdout.decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return ""

def locate_bin(name: str) -> Optional[str]:
    """Tìm đường dẫn binary. Trả về None nếu không thấy."""
    try:
        # Sử dụng 'which' để tìm đường dẫn
        path = output_suppressed(f"which {name}", root=False)
        return path if path else None
    except Exception:
        return None