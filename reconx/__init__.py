"""ReconX - passive website reconnaissance CLI.

Public entry points:
    ``reconx.run``    - run every requested module and return a report dict.
    ``reconx.cli``    - the argparse front end.
"""

from __future__ import annotations

from ._version import __version__
from .core import run

__all__ = ["__version__", "run"]
