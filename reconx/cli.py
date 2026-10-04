"""Argparse front end for ReconX.

Owns argument parsing, domain validation, and choosing between the console
summary and a machine-readable report. All intelligence lives in
:mod:`reconx.core`; this module is deliberately thin so the CLI can be tested
without touching the network.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__, core
from . import report as report_module
from .context import MAX_CONCURRENCY, ReconContext
from .report import FORMATS

__all__ = ["LEGAL_NOTICE", "build_parser", "main", "parse_modules"]

LOGGER = logging.getLogger(__name__)

LEGAL_NOTICE = core.LEGAL_NOTICE

#: Exit code used when the target or module selection is invalid.
EXIT_USAGE = 2


def parse_modules(raw: str | None) -> list[str] | None:
    """Turn a ``--modules`` string into a list of module names.

    Args:
        raw: A comma separated list such as ``"dns,http"``, or ``None``/``all``.

    Returns:
        A list of names, or ``None`` to mean "every module".

    Raises:
        ValueError: If ``raw`` is an empty selection such as ``","``.
    """
    if raw is None or not raw.strip():
        return None

    names = [part.strip().lower() for part in raw.split(",") if part.strip()]
    if not names:
        raise ValueError("--modules was given but selected no modules")
    if "all" in names:
        return None
    return names


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser for the ``reconx`` command."""
    available = ", ".join(core.available_modules())
    parser = argparse.ArgumentParser(
        prog="reconx",
        description=("Passive website reconnaissance. " + LEGAL_NOTICE),
        epilog=f"Available modules: {available}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "domain",
        nargs="?",
        default=None,
        help="domain to inspect, e.g. example.com (scheme and path are stripped)",
    )
    parser.add_argument(
        "-m",
        "--modules",
        default=None,
        metavar="LIST",
        help=f"comma separated modules to run, or 'all' (default: all of {available})",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="PATH",
        help="write the report to PATH instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=core.DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"per-request timeout in seconds (default: {core.DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "--concurrency",
        "--max-workers",
        dest="concurrency",
        type=int,
        default=8,
        metavar="N",
        help="threads used for wordlist resolution (default: 8)",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        metavar="PATH",
        help="subdomain wordlist file (default: the bundled list)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print per-module errors and timing to stderr",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ReconX {__version__}",
    )
    parser.add_argument(
        "--legal",
        action="store_true",
        help="print the authorization notice and exit",
    )
    return parser


def _build_context(args: argparse.Namespace) -> ReconContext:
    """Turn parsed CLI options into the context modules receive."""
    return ReconContext(
        timeout=args.timeout,
        concurrency=max(1, min(args.concurrency, MAX_CONCURRENCY)),
        wordlist=Path(args.wordlist) if args.wordlist else None,
    )


def _run_modules(target: str, args: argparse.Namespace) -> dict[str, Any]:
    """Execute the requested modules with the options from ``args``."""
    return core.run(target, modules=parse_modules(args.modules), context=_build_context(args))


def _render(report: dict[str, Any], fmt: str) -> str:
    """Serialize ``report`` in the requested format."""
    return report_module.render(report, fmt)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface.

    Args:
        argv: Argument list, defaulting to ``sys.argv[1:]``.

    Returns:
        ``0`` on success, ``2`` for invalid input, ``1`` if every selected
        module failed.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.legal:
        print(LEGAL_NOTICE)
        return 0

    if not args.domain:
        parser.error("the following arguments are required: domain")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    try:
        target = core.normalize_domain(args.domain)
        modules = parse_modules(args.modules)
        core.resolve_modules(modules)
    except ValueError as exc:
        parser.error(str(exc))

    if args.verbose:
        print(LEGAL_NOTICE, file=sys.stderr)

    report = _run_modules(target, args)
    output = _render(report, args.format)

    if args.output:
        with Path(args.output).open("w", encoding="utf-8") as handle:
            handle.write(output if output.endswith("\n") else output + "\n")
    else:
        print(output)

    failed = report["summary"]["modules_failed"]
    if len(failed) == len(report["modules"]):
        print(f"[-] every module failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    if failed and args.verbose:
        print(f"[-] modules with errors: {', '.join(failed)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
