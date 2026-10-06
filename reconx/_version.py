"""Single source of truth for the package version.

Kept in its own module so that ``reconx.context``, ``reconx.core`` and
``reconx.__init__`` can all read the version without a circular import: the
package ``__init__`` imports ``core``, so ``core`` cannot import ``__version__``
from the package root at module scope.
"""

from __future__ import annotations

__all__ = ["USER_AGENT_TEMPLATE", "__version__", "user_agent_string"]

__version__ = "0.2.0"

#: Project home, advertised in the User-Agent so operators can identify traffic.
PROJECT_URL = "https://github.com/hsay123/ReconX"

USER_AGENT_TEMPLATE = "ReconX/{version} (+{url}; passive recon)"


def user_agent_string(version: str = __version__) -> str:
    """Return the identifying ``User-Agent`` for a given version.

    Args:
        version: Version to advertise. Defaults to the packaged version.

    Returns:
        A ``User-Agent`` value naming the tool, its version, and its homepage.
    """
    return USER_AGENT_TEMPLATE.format(version=version, url=PROJECT_URL)
