import re
import netifaces
import logging
from typing import Optional
from scapy.all import ARP, sr1  # pylint: disable=no-name-in-module

import evillimiter.console.shell as shell
from evillimiter.common.globals import BIN_TC, BIN_IPTABLES, BIN_SYSCTL, IP_FORWARD_LOC

logger = logging.getLogger(__name__)

def get_default_interface() -> Optional[str]:
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        return gateways['default'][netifaces.AF_INET][1]
    return None

def get_default_gateway() -> Optional[str]:
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        return gateways['default'][netifaces.AF_INET][0]
    return None

def get_default_netmask(interface: str) -> Optional[str]:
    ifaddrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in ifaddrs:
        return ifaddrs[netifaces.AF_INET][0].get('netmask')
    return None

def get_mac_by_ip(interface: str, address: str) -> Optional[str]:
    packet = ARP(op=1, pdst=address)
    response = sr1(packet, timeout=3, verbose=0, iface=interface)
    if response is not None:
        return response.hwsrc
    return None

def exists_interface(interface: str) -> bool:
    return interface in netifaces.interfaces()

def flush_network_settings(interface: str) -> None:
    shell.execute_suppressed(f'{BIN_IPTABLES} -P INPUT ACCEPT')
    shell.execute_suppressed(f'{BIN_IPTABLES} -P OUTPUT ACCEPT')
    shell.execute_suppressed(f'{BIN_IPTABLES} -P FORWARD ACCEPT')

    shell.execute_suppressed(f'{BIN_IPTABLES} -t mangle -F')
    shell.execute_suppressed(f'{BIN_IPTABLES} -t nat -F')
    shell.execute_suppressed(f'{BIN_IPTABLES} -F')
    shell.execute_suppressed(f'{BIN_IPTABLES} -X')

    shell.execute_suppressed(f'{BIN_TC} qdisc del dev {interface} root')

def validate_ip_address(ip: str) -> bool:
    return re.match(r'^(\d{1,3}\.){3}(\d{1,3})$', ip) is not None

def validate_mac_address(mac: str) -> bool:
    return re.match(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', mac) is not None

def create_qdisc_root(interface: str) -> bool:
    return shell.execute_suppressed(f'{BIN_TC} qdisc add dev {interface} root handle 1:0 htb') == 0

def delete_qdisc_root(interface: str) -> bool:
    return shell.execute_suppressed(f'{BIN_TC} qdisc del dev {interface} root handle 1:0 htb') == 0

def enable_ip_forwarding() -> bool:
    return shell.execute_suppressed(f'{BIN_SYSCTL} -w {IP_FORWARD_LOC}=1') == 0

def disable_ip_forwarding() -> bool:
    return shell.execute_suppressed(f'{BIN_SYSCTL} -w {IP_FORWARD_LOC}=0') == 0

class ValueConverter:
    @staticmethod
    def byte_to_bit(v):
        return v * 8

class BitRate:
    def __init__(self, rate=0):
        self.rate = int(rate)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        r = float(self.rate)
        for unit in ['bit', 'kbit', 'mbit', 'gbit']:
            if r < 1000:
                return f"{int(r)}{unit}"
            r /= 1000
        return f"{int(r)}tbit" # Fallback

    def __mul__(self, other):
        val = other.rate if isinstance(other, BitRate) else other
        return BitRate(self.rate * val)

    @classmethod
    def from_rate_string(cls, rate_string: str):
        return cls(cls._bit_value(rate_string))

    @staticmethod
    def _bit_value(rate_string: str) -> int:
        match = re.match(r"^(\d+)([a-zA-Z]+)$", rate_string)
        if not match:
             # Try simple digit only
            if rate_string.isdigit(): return int(rate_string)
            raise ValueError('Invalid bitrate format')
        
        number, unit = int(match.group(1)), match.group(2).lower()
        units = {'bit': 1, 'kbit': 1000, 'mbit': 1000**2, 'gbit': 1000**3}
        
        if unit in units:
            return number * units[unit]
        raise ValueError('Invalid bitrate unit')

class ByteValue:
    def __init__(self, value=0):
        self.value = int(value)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        v = float(self.value)
        for unit in ['b', 'kb', 'mb', 'gb', 'tb']:
            if v < 1024:
                return f"{int(v)}{unit}"
            v /= 1024
        return f"{int(v)}pb"

    def __int__(self): return self.value
    
    def __add__(self, other): return ByteValue(self.value + (other.value if isinstance(other, ByteValue) else other))
    def __sub__(self, other): return ByteValue(self.value - (other.value if isinstance(other, ByteValue) else other))
    def __mul__(self, other): return ByteValue(self.value * (other.value if isinstance(other, ByteValue) else other))
    def __ge__(self, other): return self.value >= (other.value if isinstance(other, ByteValue) else other)

    @classmethod
    def from_byte_string(cls, byte_string: str):
        return cls(cls._byte_value(byte_string))

    @staticmethod
    def _byte_value(byte_string: str) -> int:
        match = re.match(r"^(\d+)([a-zA-Z]+)$", byte_string)
        if not match:
            if byte_string.isdigit(): return int(byte_string)
            raise ValueError('Invalid byte string')

        number, unit = int(match.group(1)), match.group(2).lower()
        units = {'b': 1, 'kb': 1024, 'mb': 1024**2, 'gb': 1024**3, 'tb': 1024**4}
        
        if unit in units:
            return number * units[unit]
        raise ValueError('Invalid byte unit')