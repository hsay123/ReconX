"""TLS certificate inspection using the standard library.

Performs one handshake against ``host:443`` and reads the leaf certificate:
who issued it, what it covers, how long it is valid for, and which protocol was
negotiated. This is the same handshake a browser would make, so it is passive
in the sense that matters — one connection, no requests, no payloads.

The handshake is made with verification disabled so that a *failing*
certificate — expired, self-signed, wrong hostname — is still reported. Those
are exactly the findings worth surfacing, and ``getpeercert()`` returns nothing
useful in that situation, so the raw DER is decoded by :mod:`reconx.x509`.
"""

from __future__ import annotations

import datetime as dt
import logging
import socket
import ssl
from typing import Any

from . import x509
from .context import ReconContext, default_context

__all__ = ["DEFAULT_PORT", "EXPIRY_WARNING_DAYS", "lookup", "read_certificate"]

LOGGER = logging.getLogger(__name__)

#: The only port inspected: HTTPS. ReconX does not port scan.
DEFAULT_PORT = 443

#: Within this many days of expiry a certificate is flagged in the warnings.
EXPIRY_WARNING_DAYS = 30


def _iso(value: dt.datetime | None) -> str:
    """Render a datetime as a stable ISO-8601 string."""
    return value.isoformat() if value else ""


def parse_certificate(der: bytes) -> dict[str, Any]:
    """Decode a DER certificate into report-friendly values.

    Args:
        der: The raw certificate bytes.

    Returns:
        A dict with issuer, subject, SANs, serial, validity dates,
        ``days_until_expiry``, ``expired`` and the protocol/cipher when known.

    Raises:
        ValueError: If the certificate cannot be parsed.
    """
    cert = x509.parse_certificate(der)

    expiry = cert.not_after
    days_until_expiry: int | None = None
    expired = False
    if expiry is not None:
        delta = expiry - dt.datetime.now(dt.UTC)
        # floor division so "expires tomorrow" reports 1, not 0.
        days_until_expiry = delta.days
        expired = delta.total_seconds() <= 0

    return {
        "issuer": ", ".join(f"{key}={value}" for key, value in (cert.issuer or {}).items()),
        "issuer_common_name": (cert.issuer or {}).get("CN", ""),
        "issuer_organization": (cert.issuer or {}).get("O", ""),
        "subject": ", ".join(f"{key}={value}" for key, value in (cert.subject or {}).items()),
        "subject_common_name": (cert.subject or {}).get("CN", ""),
        "subject_alt_names": sorted(cert.subject_alt_names or []),
        "san_count": len(cert.subject_alt_names or []),
        "serial": cert.serial or "",
        "version": cert.version,
        "not_before": _iso(cert.not_before),
        "not_after": _iso(expiry),
        "days_until_expiry": days_until_expiry,
        "expired": expired,
    }


def read_certificate(
    host: str,
    port: int = DEFAULT_PORT,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Complete one TLS handshake and describe the certificate served.

    Args:
        host: Hostname to connect to, used for SNI.
        port: Port to connect to. Defaults to 443.
        timeout: Socket timeout in seconds.

    Returns:
        A dict with the parsed certificate plus ``protocol``, ``cipher``,
        ``hostname`` and ``port`` on success, or an ``error`` key on failure.
        Never raises.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            cipher = tls.cipher()
            protocol = tls.version()
            der = tls.getpeercert(binary_form=True)
    except ssl.SSLError as exc:
        return {"error": f"TLS handshake with {host}:{port} failed: {exc}"}
    except TimeoutError:
        return {"error": f"connection to {host}:{port} timed out after {timeout:g}s"}
    except OSError as exc:
        return {"error": f"could not connect to {host}:{port}: {exc}"}

    if not der:
        return {"error": f"{host}:{port} completed a TLS handshake with no certificate"}

    try:
        result = parse_certificate(der)
    except ValueError as exc:
        return {"error": f"could not parse the certificate served by {host}: {exc}"}

    result["hostname"] = host
    result["port"] = port
    result["protocol"] = protocol or ""
    result["cipher"] = cipher[0] if cipher else ""
    return result


def lookup(domain: str, context: ReconContext | None = None) -> dict[str, Any]:
    """Inspect the TLS certificate served by ``domain``.

    Args:
        domain: A normalized domain name.
        context: Shared run settings; supplies the handshake timeout.

    Returns:
        A dict describing the certificate, or an ``error`` key. Only port 443
        is contacted: this is not a port scanner. Never raises.
    """
    ctx = context or default_context()
    try:
        result = read_certificate(domain, DEFAULT_PORT, ctx.timeout)
    except Exception as exc:  # defensive: this module must never end a run
        LOGGER.debug("TLS inspection failed for %s: %s", domain, exc)
        return {"error": f"TLS inspection failed: {exc}"}

    if "error" in result:
        return result

    warnings: list[str] = []
    days = result.get("days_until_expiry")
    if result.get("expired"):
        warnings.append(f"certificate expired on {result.get('not_after')}")
    elif isinstance(days, int) and days <= EXPIRY_WARNING_DAYS:
        warnings.append(f"certificate expires in {days} day(s), on {result.get('not_after')}")
    if not result.get("subject_alt_names"):
        warnings.append("certificate has no subject alternative names")

    result["warnings"] = warnings
    return result
