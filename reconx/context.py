"""Shared run configuration passed to every recon module.

Modules need three things the CLI knows about: how long a request may take, how
many threads may resolve names concurrently, and which wordlist to use. Passing
them as a single frozen dataclass keeps every module's signature identical and
makes the settings trivially injectable in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["ReconContext", "default_context"]

#: Upper bound on threads, to keep a run from looking like a flood.
MAX_CONCURRENCY = 32


@dataclass(frozen=True)
class ReconContext:
    """Per-run settings shared by every module.

    Attributes:
        timeout: Per-request timeout in seconds.
        concurrency: Maximum threads for parallel name resolution.
        wordlist: Optional path to a newline-delimited subdomain wordlist.
        user_agent: ``User-Agent`` sent with outbound HTTP requests.
    """

    timeout: float = 10.0
    concurrency: int = 8
    wordlist: Path | None = None
    user_agent: str = "ReconX/0.2.0 (+https://github.com/hsay123/ReconX; passive recon)"
    extras: dict[str, object] = field(default_factory=dict, compare=False)


def default_context() -> ReconContext:
    """Return the context used when a caller does not supply one."""
    return ReconContext()
