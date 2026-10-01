## Unreleased

- docs: Replaced the stale RupeeLink README with an accurate ReconX README
  (modules, install, usage, safety notice, roadmap). The old file documented an
  unrelated P2P crypto project and was actively misleading.
- chore: added pyproject.toml (package `reconx`, console script `reconx`), pinned
  requirements files, .gitignore, ruff/pytest/coverage config, and an MIT LICENSE
  so the project is installable, lintable, and testable out of the box.
- refactor: split the single-file script into a `reconx/` package (`core`,
  `dns_info`, `http_info`, `whois_info`). Modules now return dicts instead of
  printing, and a module that fails records an `error` field rather than
  taking down the run. `ReconX.py` is kept as a backward-compatible shim over
  the old function names.
- feat: argparse CLI (`reconx`, plus `python -m reconx`) with a positional
  domain, `--modules`, `--format {text,json,md,html}`, `-o/--output`,
  `--timeout`, `--concurrency`, `--wordlist`, `-v/--verbose` and `--version`.
  Input normalization accepts what people actually paste (URLs, ports, paths)
  and rejects invalid domains with exit code 2.
