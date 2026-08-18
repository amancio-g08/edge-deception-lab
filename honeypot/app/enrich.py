"""Forward-confirmed reverse DNS.

PTR alone proves nothing, it's controlled by whoever owns the address block.
Resolve PTR, resolve the hostname back, require the original IP in the answer.
"""

from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache

RESOLVER_TIMEOUT_SECONDS = 1.5


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


@lru_cache(maxsize=4096)
def forward_confirmed_rdns(ip: str) -> str | None:
    """Hostname if PTR and forward lookup agree, otherwise None.

    Cached because a scanner hits hundreds of paths and a DNS round trip per
    request would dominate response time (and leak timing).
    """
    if not ip or is_private(ip):
        return None

    socket.setdefaulttimeout(RESOLVER_TIMEOUT_SECONDS)
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return None

    try:
        _, _, forward_addresses = socket.gethostbyname_ex(hostname)
    except (socket.herror, socket.gaierror, OSError):
        return None

    return hostname if ip in forward_addresses else None
