"""Core orchestration for ReconX.

Owns three things:

* domain normalization and validation,
* the registry of available recon modules,
* :func:`run`, which executes the requested modules and assembles a report.

The central design rule is **error isolation**: a module that fails, hangs, or
raises must never take down the run. Every module is invoked defensively and
its failure is recorded in the report as an ``error`` string.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from . import dns_info, fingerprint, http_info, subdomains, tls_info, whois_info
from .context import ReconContext, default_context

__all__ = [
    "ALL_MODULES",
    "DEFAULT_TIMEOUT",
    "LEGAL_NOTICE",
    "ModuleRunner",
    "available_modules",
    "normalize_domain",
    "register_module",
    "resolve_modules",
    "run",
    "utc_now",
]

LOGGER = logging.getLogger(__name__)

#: Default per-request timeout, in seconds.
DEFAULT_TIMEOUT = 10.0

#: A recon module: takes the target domain plus the shared run context and
#: returns a JSON-safe dict. Modules must tolerate being handed a context they
#: do not care about, so the signature never grows per-module options.
ModuleRunner = Callable[[str, "ReconContext"], dict[str, Any]]

LEGAL_NOTICE = (
    "ReconX performs passive reconnaissance. Use it only on domains you own "
    "or are explicitly authorized to test. Unauthorized reconnaissance may be "
    "unlawful."
)

# A hostname label: alphanumeric, hyphen-separated, no leading/trailing hyphen.
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 ``Z`` string."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_domain(raw: str) -> str:
    """Reduce user input to a bare, lowercased hostname.

    Accepts what people actually type: full URLs, URLs with paths, ports,
    credentials, trailing slashes. A leading ``www.`` is preserved, because it
    is usually a genuinely different host.

    Args:
        raw: The user-supplied target.

    Returns:
        The hostname, lowercased and without a trailing dot.

    Raises:
        ValueError: If the input is empty, too long, or not a plausible domain.
    """
    if not raw or not raw.strip():
        raise ValueError("domain must not be empty")

    candidate = raw.strip().lower()

    # Strip a scheme if one was pasted in.
    if "://" in candidate:
        candidate = candidate.split("://", 1)[1]

    # Drop credentials, path, query, and fragment.
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[1]
    for separator in ("/", "?", "#"):
        if separator in candidate:
            candidate = candidate.split(separator, 1)[0]

    # Drop an explicit port.
    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]

    # A single trailing dot is the DNS root, not part of the name.
    candidate = candidate.rstrip(".")

    if not candidate:
        raise ValueError(f"could not parse a domain from {raw!r}")
    if len(candidate) > 253:
        raise ValueError(f"domain is too long ({len(candidate)} characters, max 253)")
    if not _DOMAIN_RE.match(candidate):
        raise ValueError(f"{raw!r} is not a valid domain name; expected something like example.com")
    return candidate


#: Registry of runnable modules, keyed by the name used with ``--modules``.
_MODULES: dict[str, ModuleRunner] = {
    "dns": dns_info.lookup,
    "http": http_info.lookup,
    "subdomains": subdomains.lookup,
    "tech": fingerprint.lookup,
    "tls": tls_info.lookup,
    "whois": whois_info.lookup,
}

#: Every module name, in the order reports present them.
ALL_MODULES: tuple[str, ...] = tuple(_MODULES)


def available_modules() -> tuple[str, ...]:
    """Return the names of every registered recon module."""
    return ALL_MODULES


def register_module(name: str, runner: ModuleRunner) -> None:
    """Add a module to the registry.

    Args:
        name: The ``--modules`` name for it.
        runner: A callable taking the domain and returning a dict.

    Raises:
        ValueError: If ``name`` is already registered.
    """
    if name in _MODULES:
        raise ValueError(f"module {name!r} is already registered")
    _MODULES[name] = runner


def resolve_modules(requested: list[str] | None) -> list[str]:
    """Turn requested module names into an ordered, valid selection.

    Args:
        requested: Names to run, or ``None``/empty for all of them.

    Returns:
        Names in :data:`ALL_MODULES` order, so report output is deterministic
        regardless of the order the user typed them in.

    Raises:
        ValueError: If any name is not a registered module.
    """
    if not requested:
        return list(ALL_MODULES)

    wanted = {name.strip().lower() for name in requested if name.strip()}
    unknown = sorted(wanted - set(_MODULES))
    if unknown:
        raise ValueError(
            f"unknown module(s): {', '.join(unknown)}. Available: {', '.join(ALL_MODULES)}"
        )
    return [name for name in ALL_MODULES if name in wanted]


def _run_one(name: str, domain: str, context: ReconContext) -> dict[str, Any]:
    """Run a single module, converting any failure into an ``error`` field."""
    runner = _MODULES[name]
    started = time.perf_counter()
    try:
        result = runner(domain, context)
    except Exception as exc:
        LOGGER.debug("module %s raised", name, exc_info=True)
        return {
            "error": f"{name} module failed: {type(exc).__name__}: {exc}",
            "duration_seconds": round(time.perf_counter() - started, 3),
        }

    if not isinstance(result, dict):
        return {
            "error": f"{name} module returned {type(result).__name__}, expected dict",
            "duration_seconds": round(time.perf_counter() - started, 3),
        }
    result.setdefault("duration_seconds", round(time.perf_counter() - started, 3))
    return result


def _summarize(results: dict[str, Any]) -> dict[str, Any]:
    """Build counts used by the console summary and the HTML report."""
    failed = sorted(
        name for name, data in results.items() if isinstance(data, dict) and "error" in data
    )
    warnings: list[str] = []
    for name, data in results.items():
        if not isinstance(data, dict):
            continue
        for warning in data.get("warnings", []) or []:
            warnings.append(f"{name}: {warning}")
    return {
        "modules_run": len(results),
        "modules_failed": failed,
        "warning_count": len(warnings),
    }


def run(
    domain: str,
    modules: list[str] | None = None,
    context: ReconContext | None = None,
) -> dict[str, Any]:
    """Run the requested recon modules against ``domain``.

    Args:
        domain: A target domain. Normalized before use.
        modules: Module names to run, or ``None`` for all of them.
        context: Shared run settings. Defaults to :func:`default_context`.

    Returns:
        A report dict with ``target``, ``generated_at``, ``duration_seconds``,
        ``modules``, ``results``, and ``summary``. A module that failed carries
        an ``error`` key in its own entry and does not affect the others.

    Raises:
        ValueError: If the domain is invalid or a module name is unknown.
    """
    target = normalize_domain(domain)
    selected = resolve_modules(modules)
    ctx = context or default_context()

    started = time.perf_counter()
    results: dict[str, Any] = {name: _run_one(name, target, ctx) for name in selected}
    duration = round(time.perf_counter() - started, 3)

    from . import __version__

    return {
        "tool": "reconx",
        "version": __version__,
        "target": target,
        "generated_at": utc_now(),
        "duration_seconds": duration,
        "modules": selected,
        "results": results,
        "summary": _summarize(results),
    }
