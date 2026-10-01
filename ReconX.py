#!/usr/bin/env python3
"""Backward-compatible shim for the original ReconX script.

The real implementation now lives in the ``reconx`` package. This file is kept
so that ``python ReconX.py`` and any existing imports of
``ReconX.get_ip`` / ``get_headers`` / ``get_whois`` / ``get_subdomains`` keep
working. The old functions printed to stdout; these return the same data as
dicts and print it in the same shape, so old callers see no difference.

New code should use the CLI instead::

    reconx example.com --format json
"""

from __future__ import annotations

import sys
from typing import Any

from reconx import __version__, core, dns_info, http_info, whois_info

__all__ = ["get_headers", "get_ip", "get_subdomains", "get_whois", "main"]

LEGAL_BANNER = core.LEGAL_NOTICE


def get_ip(domain: str) -> dict[str, Any]:
    """Return the resolved A/AAAA records for ``domain``.

    Args:
        domain: A domain name.

    Returns:
        ``{"a": [...], "aaaa": [...]}``; empty lists when nothing resolved.
    """
    target = core.normalize_domain(domain)
    records = dns_info.lookup(target).get("records", {})
    return {"a": records.get("A", []), "aaaa": records.get("AAAA", [])}


def get_headers(domain: str) -> dict[str, Any]:
    """Return the HTTP response headers for ``domain``.

    Args:
        domain: A domain name.

    Returns:
        A dict with ``status_code``, ``url``, and ``headers``.
    """
    target = core.normalize_domain(domain)
    result = http_info.lookup(target)
    if "error" in result:
        return {"error": result["error"], "status_code": None, "url": None, "headers": {}}
    return {
        "status_code": result.get("status_code"),
        "url": result.get("url"),
        "headers": result.get("headers", {}),
    }


def get_whois(domain: str) -> dict[str, Any]:
    """Return WHOIS registration data for ``domain``.

    Args:
        domain: A domain name.

    Returns:
        A dict of registration fields, or one with an ``error`` key.
    """
    return whois_info.lookup(core.normalize_domain(domain))


def get_subdomains(domain: str) -> dict[str, Any]:
    """Report that subdomain discovery moved into the CLI.

    The original implementation shelled out to ``dig *.domain``, which is not
    valid DNS and never finds anything. Subdomain discovery is being rebuilt on
    certificate transparency plus a capped wordlist; until that module lands,
    this reports the situation instead of pretending it worked.

    Args:
        domain: A domain name.

    Returns:
        A dict with an empty ``subdomains`` list and an explanatory ``note``.
    """
    core.normalize_domain(domain)  # validate, so bad input still raises here
    return {
        "subdomains": [],
        "note": (
            "subdomain discovery moved to the reconx package: "
            "run 'reconx example.com --modules subdomains'"
        ),
    }


def main() -> int:
    """Run the legacy interactive prompt, or print help when args are given."""
    if len(sys.argv) > 1:
        print(f"ReconX {__version__}", file=sys.stderr)
        print(
            "This file is a compatibility shim. Use the CLI:\n"
            "    reconx example.com --format json\n"
            "or:  python -m reconx example.com",
            file=sys.stderr,
        )
        return 0

    print("===== Website Information Gatherer =====\n")
    print(LEGAL_BANNER + "\n")

    try:
        domain = input("Enter domain (example.com): ").strip()
        target = core.normalize_domain(domain)
    except (EOFError, KeyboardInterrupt):
        print()
        return 130
    except ValueError as exc:
        print(f"[-] {exc}")
        return 2

    result = core.run(target)

    ips = result["results"]["dns"].get("records", {}).get("A", [])
    print(f"[+] IP Address: {', '.join(ips) if ips else 'not resolved'}")

    headers = result["results"]["http"]
    if "error" in headers:
        print(f"[-] Could not fetch headers: {headers['error']}")
    else:
        print("\n[+] Server Headers:")
        for key, value in headers.get("headers", {}).items():
            print(f"    {key}: {value}")

    who = result["results"]["whois"]
    if "error" in who:
        print(f"[-] Whois lookup failed: {who['error']}")
    else:
        print("\n[+] Whois Information:")
        for key, value in who.items():
            print(f"    {key}: {value}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
