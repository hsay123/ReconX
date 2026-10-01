"""HTTP(S) response inspection.

Tries HTTPS first and falls back to HTTP, since a domain may only serve one
protocol. Redirects are walked manually one hop at a time rather than handed to
``requests``, so the report can show the real chain a user would follow instead
of only the destination.

The module also audits security headers, because "does this site send HSTS and
a CSP" is the first question that comes up once you have seen the headers.
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from .context import ReconContext, default_context

__all__ = [
    "SECURITY_HEADERS",
    "audit_security_headers",
    "build_session",
    "lookup",
    "user_agent",
]

LOGGER = logging.getLogger(__name__)

#: Security headers audited in the response, and what each one is for.
SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "forces HTTPS for future requests",
    "Content-Security-Policy": "restricts where scripts and resources may load from",
    "X-Frame-Options": "prevents clickjacking via framing",
    "X-Content-Type-Options": "stops MIME-type sniffing",
    "Referrer-Policy": "controls how much referrer data is leaked",
    "Permissions-Policy": "limits access to sensitive browser features",
}

#: Maximum hops followed before giving up on a redirect loop.
MAX_REDIRECTS = 5


def user_agent(context: ReconContext | None = None) -> str:
    """Return the ``User-Agent`` identifying ReconX to operators."""
    return (context or default_context()).user_agent


def build_session(context: ReconContext | None = None) -> requests.Session:
    """Return a session carrying ReconX's identifying headers.

    Redirects are disabled per request so the chain can be walked manually;
    ``max_redirects`` bounds how many hops will ever be followed.
    """
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": user_agent(context),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
    )
    session.max_redirects = MAX_REDIRECTS
    return session


def audit_security_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Score a response's security headers.

    Args:
        headers: Response headers with lowercased keys.

    Returns:
        A dict with the ``present`` and ``missing`` header names and a
        ``score`` out of ``total``. This is a presence check, not a
        correctness check: a present-but-empty CSP still counts as present.
    """
    present = [name for name in SECURITY_HEADERS if name.lower() in headers]
    missing = [name for name in SECURITY_HEADERS if name.lower() not in headers]
    return {
        "present": present,
        "missing": missing,
        "score": len(present),
        "total": len(SECURITY_HEADERS),
        "grade": _grade(len(present), len(SECURITY_HEADERS)),
    }


def _grade(score: int, total: int) -> str:
    """Map a header score onto a coarse letter grade."""
    ratio = score / total if total else 0.0
    if ratio >= 0.99:
        return "A"
    if ratio >= 0.66:
        return "B"
    if ratio >= 0.33:
        return "C"
    return "D"


def _fetch_chain(
    session: requests.Session,
    url: str,
    timeout: float,
) -> tuple[requests.Response | None, list[dict[str, Any]], str | None]:
    """Walk the redirect chain starting at ``url``.

    Args:
        session: Session to make requests with.
        url: Where to start.
        timeout: Per-request timeout in seconds.

    Returns:
        The final response, the chain of hops (each ``{url, status_code,
        location}``), and an error string if the walk failed.
    """
    chain: list[dict[str, Any]] = []
    current = url

    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = session.get(current, timeout=timeout, allow_redirects=False)
        except requests.Timeout:
            return None, chain, f"request to {current} timed out after {timeout:g}s"
        except requests.TooManyRedirects:
            return None, chain, "too many redirects"
        except requests.RequestException as exc:
            return None, chain, f"request to {current} failed: {exc}"

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location", "")
            chain.append(
                {
                    "url": current,
                    "status_code": response.status_code,
                    "location": urlparse(location).hostname or location,
                }
            )
            if not location:
                return None, chain, f"{current} redirected without a Location header"
            current = urljoin(current, location)
            continue

        return response, chain, None

    return None, chain, f"exceeded {MAX_REDIRECTS} redirects"


def lookup(
    domain: str,
    context: ReconContext | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Fetch and describe the HTTP(S) response for ``domain``.

    HTTPS is attempted first; plain HTTP is the fallback.

    Args:
        domain: A normalized domain name.
        context: Shared run settings; supplies the per-request timeout.
        session: An optional prebuilt session, mainly for tests.

    Returns:
        A dict describing the final URL, status, timing, redirect chain, all
        response headers, and the security-header audit. Includes an ``error``
        key when neither protocol responded. Never raises.
    """
    ctx = context or default_context()
    active = session or build_session(ctx)
    owns_session = session is None
    attempts: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            started = time.perf_counter()
            response, chain, error = _fetch_chain(active, url, ctx.timeout)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

            if error is not None:
                errors.append(f"{scheme}: {error}")
                attempts.append({"scheme": scheme, "url": url, "error": error})
                continue

            if response is None:  # pragma: no cover - defensive
                errors.append(f"{scheme}: no response")
                continue

            attempts.append(
                {
                    "scheme": scheme,
                    "url": url,
                    "status_code": response.status_code,
                    "final_url": response.url,
                    "elapsed_ms": elapsed_ms,
                }
            )

            headers = {key.lower(): value for key, value in response.headers.items()}
            audit = audit_security_headers(headers)
            warnings: list[str] = []

            if chain:
                warnings.append(f"followed {len(chain)} redirect(s) to reach the final URL")
            if not audit["present"]:
                warnings.append("no security headers present")
            for missing in audit["missing"]:
                warnings.append(f"missing security header: {missing}")
            if errors:
                warnings.append(f"{scheme} answered after {errors[-1]}")

            content_length = headers.get("content-length", "")
            return {
                "url": response.url,
                "final_url": response.url,
                "status_code": response.status_code,
                "reason": response.reason or "",
                "scheme": scheme,
                "response_time_ms": elapsed_ms,
                "redirects": chain,
                "redirect_count": len(chain),
                "headers": dict(sorted(headers.items())),
                "header_count": len(headers),
                "security_headers": audit,
                "attempts": attempts,
                "content_type": headers.get("content-type", ""),
                "content_length": int(content_length) if content_length.isdigit() else None,
                "warnings": warnings,
            }

        return {
            "error": f"could not reach {domain} over https or http",
            "attempts": attempts,
            "warnings": errors,
        }
    finally:
        if owns_session:
            active.close()
