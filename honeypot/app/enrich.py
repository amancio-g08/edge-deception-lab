"""Source enrichment: forward-confirmed reverse DNS.

FCrDNS is the check a production bot manager runs before trusting a crawler's
identity claim: resolve the PTR record for the source address, then resolve that
hostname back and confirm the original address is in the answer. A PTR alone is
attacker-controlled and proves nothing.
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
    """Return the hostname only when PTR and forward lookup agree.

    Cached: the same scanner will hit hundreds of paths, and a DNS round trip
    per request would dominate response time and leak timing information.
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
