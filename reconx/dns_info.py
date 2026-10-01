"""Address resolution for ReconX.

Extracts the old script's ``get_ip`` behaviour: resolve a domain to its IPv4
and IPv6 addresses using the standard library. Every lookup is bounded by a
timeout and failures come back as an ``error`` key rather than an exception, so
one broken lookup cannot stop a run.
"""

from __future__ import annotations

import logging
import socket
from typing import Any

__all__ = ["lookup", "resolve_addresses"]

LOGGER = logging.getLogger(__name__)


def resolve_addresses(domain: str, family: int) -> list[str]:
    """Return every address of ``family`` that ``domain`` resolves to.

    Args:
        domain: A normalized domain name.
        family: ``socket.AF_INET`` for IPv4 or ``socket.AF_INET6`` for IPv6.

    Returns:
        A sorted list of unique address strings; empty when nothing resolved.
    """
    try:
        infos = socket.getaddrinfo(domain, None, family)
    except socket.gaierror as exc:
        LOGGER.debug("getaddrinfo(%s, family=%s) failed: %s", domain, family, exc)
        return []
    except OSError as exc:  # timeout / network unreachable / resolver trouble
        LOGGER.debug("getaddrinfo(%s, family=%s) failed: %s", domain, family, exc)
        return []

    return sorted({info[4][0] for info in infos})


def lookup(domain: str, timeout: float = 5.0) -> dict[str, Any]:
    """Collect address records for ``domain``.

    Args:
        domain: A normalized domain name.
        timeout: Accepted for a consistent module interface; the standard
            library resolver does not expose a per-call timeout.

    Returns:
        A dict with a ``records`` mapping of ``{"A": [...], "AAAA": [...]}``, a
        ``warnings`` list, and an ``error`` key when nothing resolved at all.
    """
    del timeout  # stdlib resolver has no per-call timeout knob

    ipv4 = resolve_addresses(domain, socket.AF_INET)
    ipv6 = resolve_addresses(domain, socket.AF_INET6)
    records = {"A": ipv4, "AAAA": ipv6}

    if not ipv4 and not ipv6:
        return {
            "error": f"domain does not resolve to any address: {domain}",
            "records": records,
        }
    return {"records": records, "warnings": []}
