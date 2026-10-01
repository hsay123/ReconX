"""WHOIS registration lookups.

Wraps ``python-whois`` and flattens its wildly inconsistent result objects
(``dict`` on some TLDs, objects with attributes on others) into plain JSON-safe
values.
"""

from __future__ import annotations

import logging
from typing import Any

import whois

from .context import ReconContext

__all__ = ["REGISTRAR_FIELDS", "lookup", "parse_whois_data"]

LOGGER = logging.getLogger(__name__)

#: Fields worth surfacing, mapped to their output key.
REGISTRAR_FIELDS: dict[str, str] = {
    "registrar": "registrar",
    "registrant_name": "registrant",
    "registrant_organization": "organization",
    "registrant_country": "country",
    "creation_date": "created",
    "expiration_date": "expires",
    "updated_date": "updated",
    "name_servers": "name_servers",
    "status": "status",
    "emails": "emails",
    "dnssec": "dnssec",
}


def _clean(value: Any) -> Any:
    """Return a JSON-serializable version of ``value``."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    # date/datetime objects expose an isoformat() method.
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return isoformat()
    if isinstance(value, dict):
        return {str(k): _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_clean(v) for v in value]
    return str(value)


def _normalize(value: Any, single: bool) -> Any:
    """Collapse WHOIS's one-or-many fields into a consistent list or scalar."""
    cleaned = _clean(value)
    if single and isinstance(cleaned, list):
        return cleaned[0] if cleaned else None
    return cleaned


def parse_whois_data(data: Any) -> dict[str, Any]:
    """Flatten a raw ``python-whois`` result into a report-friendly dict.

    Args:
        data: Whatever ``whois.whois()`` returned.

    Returns:
        A dict keyed by the names in :data:`REGISTRAR_FIELDS`, containing only
        the fields the TLD actually published.
    """
    if data is None:
        return {}

    # python-whois returns a dict-like object, but some code paths hand back a
    # plain object with attributes. Support both.
    def read(field: str) -> Any:
        if isinstance(data, dict):
            return data.get(field)
        return getattr(data, field, None)

    parsed: dict[str, Any] = {}
    for field, key in REGISTRAR_FIELDS.items():
        value = read(field)
        if value is None or value == [] or value == "":
            continue
        # Everything except these three is consistently a list upstream.
        single = field in {"registrar", "registrant_name", "registrant_country"}
        parsed[key] = _normalize(value, single)
    return parsed


def lookup(domain: str, context: ReconContext | None = None) -> dict[str, Any]:
    """Look up WHOIS registration data for ``domain``.

    Args:
        domain: A normalized domain name.
        context: Shared run settings. Unused here: python-whois manages its own
            socket timeouts, which is why WHOIS is not covered by --timeout.

    Returns:
        A dict with parsed registration fields, plus an ``error`` key holding a
        short message when the lookup fails. Never raises.
    """
    del context  # accepted for a uniform module signature; see the docstring
    try:
        data = whois.whois(domain)
    except Exception as exc:  # third-party lib raises broadly
        LOGGER.debug("whois lookup failed for %s: %s", domain, exc)
        return {"error": f"whois lookup failed: {exc}"}

    if not data:
        return {"error": f"no whois data published for {domain}"}

    parsed = parse_whois_data(data)
    if not parsed:
        return {"error": f"whois response for {domain} contained no known fields"}
    return parsed
