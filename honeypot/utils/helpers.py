"""
Helper utilities for parsing and safety checks
"""

import ipaddress

def is_private_or_local(host: str) -> bool:
    """
    Return True if host is loopback or in private IPv4 ranges.
    Used to enforce safety for simulation.
    """
    try:
        ip = ipaddress.ip_address(host)
    except Exception:
        # try to resolve names like 'localhost'
        if host in ("localhost", "127.0.0.1"):
            return True
        return False

    # IPv4/IPv6 private / loopback checks
    return ip.is_private or ip.is_loopback
