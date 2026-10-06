"""Shared run configuration passed to every recon module.

Modules need three things the CLI knows about: how long a request may take, how
many threads may resolve names concurrently, and which wordlist to use. Passing
them as a single frozen dataclass keeps every module's signature identical and
makes the settings trivially injectable in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ._version import user_agent_string

__all__ = ["MAX_CONCURRENCY", "ReconContext", "default_context"]

#: Upper bound on threads, to keep a run from looking like a flood.
MAX_CONCURRENCY = 32


def _default_user_agent() -> str:
    """Build the default ``User-Agent`` from the packaged version.

    Derived rather than hardcoded so a release bump cannot leave ReconX
    advertising a stale version to every server it touches.
    """
    return user_agent_string()


@dataclass(frozen=True)
class ReconContext:
    """Per-run settings shared by every module.

    Attributes:
        timeout: Per-request timeout in seconds.
        concurrency: Maximum threads for parallel name resolution.
        wordlist: Optional path to a newline-delimited subdomain wordlist.
        user_agent: ``User-Agent`` sent with outbound HTTP requests. Derived
            from the packaged version unless overridden.
        no_crtsh: Skip the crt.sh transparency lookup when True.
    """

    timeout: float = 10.0
    concurrency: int = 8
    wordlist: Path | None = None
    user_agent: str = field(default_factory=_default_user_agent)
    extras: dict[str, object] = field(default_factory=dict, compare=False)
    no_crtsh: bool = False


def default_context() -> ReconContext:
    """Return the context used when a caller does not supply one."""
    return ReconContext()
