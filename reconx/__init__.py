"""ReconX - passive website reconnaissance CLI.

Public entry points:
    ``reconx.run``    - run every requested module and return a report dict.
    ``reconx.cli``    - the argparse front end.
"""

from __future__ import annotations

from .core import run

__version__ = "0.2.0"

__all__ = ["__version__", "run"]
