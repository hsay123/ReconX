"""DNS record collection via dnspython.

Replaces the previous ``subprocess dig`` approach: querying dnspython directly
gives per-record-type timeouts, structured results, and no external binary
dependency. Records that do not exist (``NXDOMAIN``/``NoAnswer``) are simply
omitted rather than treated as errors, because a domain legitimately has no
MX record.
"""

from __future__ import annotations

import logging
from typing import Any

import dns.exception
import dns.rdatatype
import dns.resolver

from .context import ReconContext, default_context

__all__ = [
    "DEFAULT_RESOLVER",
    "RECORD_TYPES",
    "lookup",
    "resolve_all",
    "resolve_all_with_errors",
]

LOGGER = logging.getLogger(__name__)

#: Record types collected, in the order they are reported.
RECORD_TYPES: tuple[str, ...] = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")

#: The resolver every lookup shares. Keeping one instance lets connection reuse
#: and a single configurable timeout apply to the whole run.
DEFAULT_RESOLVER = dns.resolver.Resolver()


def _normalize_rdata(rdata: Any, rtype: str) -> Any:
    """Turn a dnspython rdata object into JSON-safe primitives."""
    if rtype == "MX":
        return {"preference": int(rdata.preference), "exchange": str(rdata.exchange).rstrip(".")}
    if rtype == "SOA":
        return {
            "mname": str(rdata.mname).rstrip("."),
            "rname": str(rdata.rname).rstrip("."),
            "serial": int(rdata.serial),
            "refresh": int(rdata.refresh),
            "retry": int(rdata.retry),
            "expire": int(rdata.expire),
            "minimum": int(rdata.minimum),
        }
    if rtype == "TXT":
        # TXT rdata is a sequence of byte strings that must be concatenated.
        return "".join(bytes(chunk).decode("utf-8", errors="replace") for chunk in rdata.strings)
    if rtype == "NS":
        return str(rdata).rstrip(".")
    if rtype == "CNAME":
        return str(rdata).rstrip(".")
    return str(rdata)


def _query(
    domain: str,
    rtype: str,
    resolver: dns.resolver.Resolver,
    timeout: float,
) -> tuple[list[Any], str | None, bool]:
    """Query one record type, returning ``(values, error, fatal)``.

    ``fatal`` marks a failure that makes every remaining query pointless: once
    a name is known not to exist, no other record type can answer for it.
    """
    try:
        answers = resolver.resolve(domain, rtype, raise_on_no_answer=False, lifetime=timeout)
    except dns.resolver.NXDOMAIN:
        return [], f"{domain} does not exist (NXDOMAIN)", True
    except dns.resolver.NoAnswer:
        # Record type absent, which is normal and not a failure.
        return [], None, False
    except dns.resolver.NoNameservers:
        return [], f"no nameserver could answer the {rtype} query", False
    except dns.resolver.LifetimeTimeout:
        return [], f"{rtype} query timed out after {timeout:g}s", False
    except dns.exception.DNSException as exc:
        return [], f"{rtype} query failed: {exc}", False

    values = [_normalize_rdata(rdata, rtype) for rdata in answers]
    if not values and rtype == "CNAME":
        return [], None, False
    return values, None, False


def resolve_all(
    domain: str,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = 5.0,
) -> dict[str, list[Any]]:
    """Resolve every record type in :data:`RECORD_TYPES` for ``domain``.

    Args:
        domain: A normalized domain name.
        resolver: Resolver to use. Defaults to the shared :data:`DEFAULT_RESOLVER`.
        timeout: Per-query lifetime in seconds.

    Returns:
        A mapping of record type to a list of JSON-safe values. Types that do
        not exist are absent from the mapping.
    """
    records, _ = resolve_all_with_errors(domain, resolver, timeout)
    return records


def resolve_all_with_errors(
    domain: str,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = 5.0,
) -> tuple[dict[str, list[Any]], list[str]]:
    """Resolve every record type and keep the per-type errors.

    Separating the errors from the records lets :func:`lookup` explain *why* a
    domain produced nothing (NXDOMAIN, a timeout, no nameserver answering),
    instead of only reporting that it did.

    Args:
        domain: A normalized domain name.
        resolver: Resolver to use. Defaults to the shared :data:`DEFAULT_RESOLVER`.
        timeout: Per-query lifetime in seconds.

    Returns:
        A ``(records, errors)`` pair.
    """
    active = resolver or DEFAULT_RESOLVER
    records: dict[str, list[Any]] = {}
    errors: list[str] = []
    for rtype in RECORD_TYPES:
        values, error, fatal = _query(domain, rtype, active, timeout)
        if values:
            records[rtype] = values
        if error:
            LOGGER.debug("%s for %s: %s", rtype, domain, error)
            errors.append(error)
        if fatal:
            # NXDOMAIN: the name itself is absent, so the remaining types
            # cannot produce anything and would only repeat the same error.
            break
    return records, errors


def lookup(
    domain: str,
    context: ReconContext | None = None,
    resolver: dns.resolver.Resolver | None = None,
) -> dict[str, Any]:
    """Collect DNS records for ``domain``.

    Args:
        domain: A normalized domain name.
        context: Shared run settings; supplies the per-query timeout.
        resolver: Resolver to use. Defaults to the shared :data:`DEFAULT_RESOLVER`.

    Returns:
        A dict with a ``records`` mapping plus a ``warnings`` list. Returns an
        ``error`` key only when nothing at all could be resolved.
    """
    ctx = context or default_context()
    records, errors = resolve_all_with_errors(domain, resolver, min(ctx.timeout, 10.0))
    if not records:
        # Deduplicate: every record type reports the same underlying failure,
        # so surfacing all seven would be noise.
        detail = errors[0] if errors else "the domain has no DNS records"
        return {"error": f"no DNS records resolved for {domain}: {detail}", "records": {}}

    warnings: list[str] = []
    if "A" not in records and "AAAA" not in records:
        warnings.append("no A or AAAA record: the host may not resolve to an address")
    return {"records": records, "warnings": warnings}
