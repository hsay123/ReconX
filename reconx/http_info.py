"""HTTP(S) response inspection for ReconX.

Extracts the old script's ``get_headers`` behaviour: fetch a domain over HTTPS,
fall back to plain HTTP, and report the status, timing and response headers.
Every request is bounded by a timeout and returns an ``error`` key on failure
instead of raising.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import requests

from .context import ReconContext, default_context

__all__ = ["build_session", "lookup", "user_agent"]

LOGGER = logging.getLogger(__name__)


def user_agent(context: ReconContext | None = None) -> str:
    """Return the ``User-Agent`` to identify ReconX to operators."""
    return (context or default_context()).user_agent


def build_session(context: ReconContext | None = None) -> requests.Session:
    """Return a session carrying ReconX's identifying headers."""
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": user_agent(context),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
    )
    return session


def lookup(
    domain: str,
    context: ReconContext | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Fetch the HTTP(S) response for ``domain``.

    HTTPS is attempted first; plain HTTP is the fallback.

    Args:
        domain: A normalized domain name.
        context: Shared run settings; supplies the per-request timeout.
        session: An optional prebuilt session, mainly for tests.

    Returns:
        A dict with ``url``, ``status_code``, ``response_time_ms`` and
        lowercased ``headers``, or an ``error`` key when neither protocol
        responded. Never raises.
    """
    ctx = context or default_context()
    timeout = ctx.timeout
    active = session or build_session()
    owns_session = session is None
    attempts: list[dict[str, Any]] = []

    try:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            started = time.perf_counter()
            try:
                response = active.get(url, timeout=timeout)
            except requests.RequestException as exc:
                error = f"{scheme}: {type(exc).__name__}: {exc}"
                LOGGER.debug("request to %s failed: %s", url, exc)
                attempts.append({"scheme": scheme, "url": url, "error": error})
                continue

            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
            headers = {key.lower(): value for key, value in response.headers.items()}
            attempts.append(
                {
                    "scheme": scheme,
                    "url": url,
                    "status_code": response.status_code,
                    "final_url": response.url,
                    "elapsed_ms": elapsed_ms,
                }
            )
            return {
                "url": response.url,
                "final_url": response.url,
                "status_code": response.status_code,
                "reason": response.reason or "",
                "response_time_ms": elapsed_ms,
                "headers": dict(sorted(headers.items())),
                "header_count": len(headers),
                "attempts": attempts,
                "warnings": [],
            }

        return {
            "error": f"could not reach {domain} over https or http",
            "attempts": attempts,
        }
    finally:
        if owns_session:
            active.close()
