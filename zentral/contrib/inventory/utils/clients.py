import ipaddress
import logging


__all__ = [
    "clean_ip_address",
]


logger = logging.getLogger("zentral.contrib.inventory.utils.clients")


def clean_ip_address(addr):
    if not isinstance(addr, str):
        return None
    addr = addr.strip()
    if not addr:
        return None
    try:
        addr = ipaddress.IPv4Address(addr)
    except ValueError:
        try:
            addr = ipaddress.IPv6Address(addr)
        except ValueError:
            return None
        else:
            if addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            else:
                return str(addr)
    else:
        return str(addr)
