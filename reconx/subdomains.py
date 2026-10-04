"""Passive subdomain discovery.

Two sources, combined and deduplicated:

* **Certificate Transparency** (crt.sh) — names that appeared in a TLS
  certificate, so they are real hosts somebody asked a CA to vouch for.
* **Wordlist resolution** — a short list of common labels resolved against the
  target, capped and rate limited so a run stays a trickle rather than a flood.

Both are passive or near-passive: one HTTPS query to a public transparency
aggregator, and DNS queries for names that are already guessable. Nothing here
brute forces, scans ports, or probes discovered hosts.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.resources import files
from pathlib import Path
from typing import Any

import dns.exception
import dns.resolver
import requests

from .context import MAX_CONCURRENCY, ReconContext, default_context

__all__ = [
    "CRTSH_URL",
    "DEFAULT_WORDLIST",
    "discover",
    "load_wordlist",
    "lookup",
    "query_crtsh",
    "resolve_names",
]

LOGGER = logging.getLogger(__name__)

#: Certificate transparency aggregator. Public and free, but slow and rate
#: limited, so its failure is never fatal.
CRTSH_URL = "https://crt.sh/"

#: The wordlist shipped inside the package.
DEFAULT_WORDLIST = Path(str(files("reconx").joinpath("wordlists/default_subdomains.txt")))

#: cap on the transparency query, which is known to be slow
CRTSH_TIMEOUT = 30.0


def load_wordlist(path: Path | None = None) -> list[str]:
    """Read a subdomain wordlist.

    Args:
        path: File to read, or ``None`` for the bundled default.

    Returns:
        Sorted, de-duplicated labels. Blank lines and ``#`` comments are skipped.

    Raises:
        OSError: If an explicitly requested wordlist cannot be read.
    """
    source = path or DEFAULT_WORDLIST
    words = set()
    for line in source.read_text(encoding="utf-8").splitlines():
        entry = line.split("#", 1)[0].strip().lower()
        if entry:
            words.add(entry)
    return sorted(words)


def _in_scope(name: str, domain: str) -> bool:
    """Return whether ``name`` is a host under ``domain``.

    crt.sh returns the queried domain itself and unrelated third-party names
    from CNAME chains, so both are filtered out here rather than polluting the
    results.
    """
    name = name.lower().strip().rstrip(".")
    domain = domain.lower().rstrip(".")
    if not name or "*" in name:
        return False
    return name == domain or name.endswith(f".{domain}")


def query_crtsh(
    domain: str,
    context: ReconContext | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Ask crt.sh for every name it has seen issued for ``domain``.

    Args:
        domain: A normalized domain name.
        context: Shared run settings; supplies the user agent.
        session: An optional prebuilt session, mainly for tests.

    Returns:
        ``{"names": [...], "error": None}`` on success, or ``{"names": [],
        "error": "..."}`` when the aggregator is unreachable or unhelpful.
        Never raises: crt.sh is frequently slow and sometimes answers 502.
    """
    ctx = context or default_context()
    owns_session = session is None
    active = session or requests.Session()

    try:
        response = active.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=CRTSH_TIMEOUT,
            headers={"User-Agent": ctx.user_agent},
        )
    except requests.RequestException as exc:
        LOGGER.debug("crt.sh request failed for %s: %s", domain, exc)
        return {"names": [], "error": f"crt.sh lookup failed: {exc}"}
    finally:
        if owns_session:
            active.close()

    if response.status_code != 200:
        return {
            "names": [],
            "error": f"crt.sh returned HTTP {response.status_code}",
        }

    try:
        entries = response.json()
    except ValueError as exc:
        return {"names": [], "error": f"crt.sh returned invalid JSON: {exc}"}

    if not isinstance(entries, list):
        return {"names": [], "error": "crt.sh returned an unexpected payload shape"}

    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            value = entry.get(field)
            if isinstance(value, str):
                # name_value may hold several newline-separated names.
                for candidate in value.splitlines():
                    if _in_scope(candidate, domain):
                        names.add(candidate.lower().strip().rstrip("."))

    if not names:
        return {"names": [], "error": f"crt.sh had no certificates for {domain}"}
    return {"names": sorted(names), "error": None}


def _resolves(name: str, timeout: float) -> bool:
    """Return whether ``name`` resolves to any A or AAAA record."""
    resolver = dns.resolver.Resolver()
    for rtype in ("A", "AAAA"):
        try:
            if resolver.resolve(name, rtype, raise_on_no_answer=False, lifetime=timeout):
                return True
        except dns.resolver.NXDOMAIN:
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            continue
        except (dns.resolver.LifetimeTimeout, dns.exception.DNSException) as exc:
            LOGGER.debug("resolving %s (%s) failed: %s", name, rtype, exc)
            continue
    return False


def resolve_names(
    domain: str,
    words: list[str],
    context: ReconContext | None = None,
) -> dict[str, Any]:
    """Resolve ``<word>.<domain>`` for every word, concurrently and capped.

    Concurrency is clamped to :data:`~reconx.context.MAX_CONCURRENCY` and each
    DNS query has a lifetime, so this stays a light trickle of traffic even
    against a large wordlist.

    Args:
        domain: A normalized domain name.
        words: Labels to prepend to ``domain``.
        context: Shared run settings; supplies timeout and concurrency.

    Returns:
        ``{"found": [...], "checked": int}``.
    """
    ctx = context or default_context()
    workers = max(1, min(ctx.concurrency, MAX_CONCURRENCY))
    candidates = [f"{word}.{domain}" for word in words]

    found: list[str] = []
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="reconx-dns") as pool:
        futures = {pool.submit(_resolves, name, ctx.timeout): name for name in candidates}
        for future in as_completed(futures):
            try:
                if future.result():
                    found.append(futures[future])
            except Exception as exc:  # a single bad name must not kill the sweep
                LOGGER.debug("word %s raised: %s", futures[future], exc)

    return {"found": sorted(set(found)), "checked": len(candidates)}


def _has_wildcard(domain: str, timeout: float) -> bool:
    """Detect wildcard DNS by resolving an implausible random label.

    A wildcard zone answers every name, which would otherwise make every word
    in the list look like a hit.
    """
    return _resolves(f"reconx-wildcard-probe-{id(domain) & 0xFFFFFF:x}.{domain}", timeout)


def discover(
    domain: str,
    context: ReconContext | None = None,
    wordlist: Path | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Combine both sources into one deduplicated, sorted list.

    Args:
        domain: A normalized domain name.
        context: Shared run settings.
        wordlist: Optional wordlist path; defaults to the bundled list.
        session: Optional session for the crt.sh call, mainly for tests.

    Returns:
        A dict with ``subdomains``, per-source counts, and any ``warnings``.
        Records an ``error`` only when *both* sources fail.
    """
    ctx = context or default_context()
    warnings: list[str] = []

    skip_crtsh = bool(getattr(ctx, "no_crtsh", False) or ctx.extras.get("no_crtsh"))
    if skip_crtsh:
        crtsh: dict[str, Any] = {"names": [], "error": None}
    else:
        crtsh = query_crtsh(domain, ctx, session)
        if crtsh["error"]:
            warnings.append(crtsh["error"])
    passive = set(crtsh["names"])

    words = load_wordlist(wordlist if wordlist is not None else ctx.wordlist)
    wildcard = _has_wildcard(domain, ctx.timeout)
    brute = resolve_names(domain, words, ctx)
    if wildcard:
        warnings.append(
            "wildcard DNS detected: every wordlist name resolves, so wordlist "
            "results are unreliable and were ignored"
        )
    active = set() if wildcard else set(brute["found"])

    combined = sorted(passive | active)
    if not combined:
        return {
            "error": f"no subdomains discovered for {domain}",
            "subdomains": [],
            "sources": {"crtsh": 0, "wordlist": 0},
            "wildcard_dns": wildcard,
            "warnings": warnings,
        }

    return {
        "subdomains": combined,
        "count": len(combined),
        "sources": {
            "crtsh": len(passive),
            "wordlist": len(active),
            "wordlist_checked": brute["checked"],
        },
        "wildcard_dns": wildcard,
        "warnings": warnings,
    }


def lookup(
    domain: str,
    context: ReconContext | None = None,
    wordlist: Path | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Discover subdomains of ``domain``.

    Args:
        domain: A normalized domain name.
        context: Shared run settings.
        wordlist: Optional wordlist path; defaults to the bundled list.
        session: Optional session for the crt.sh call, mainly for tests.

    Returns:
        A dict as described by :func:`discover`. Never raises.
    """
    try:
        return discover(domain, context, wordlist, session)
    except Exception as exc:  # defensive: this module must never end a run
        LOGGER.debug("subdomain discovery failed for %s: %s", domain, exc)
        return {"error": f"subdomain discovery failed: {exc}", "subdomains": []}
