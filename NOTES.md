# ReconX — Engineering Notes

Scratchpad for the ongoing ReconX refactor. Kept intentionally short.

## Baseline

- Baseline commit count at the start of the refactor: **19** (`git rev-list --count HEAD` on
  `8cdffda`). The refactor targets at least 30 commits (baseline + 11).
- Baseline commit: `8cdffda docs: update changelog` on `main`.

## Working plan

See [TODO.md](TODO.md) for the tracked checklist. Summary of the 13 planned commits:

1. docs — accurate README
2. chore — `pyproject.toml`, requirements, `.gitignore`, ruff config, LICENSE
3. refactor — `reconx/` package returning dicts, `ReconX.py` becomes a shim
4. feat — argparse CLI + domain normalisation
5. feat — DNS module (dnspython), drop the broken `subprocess dig "*.domain"` logic
6. feat — subdomain discovery (crt.sh + capped wordlist resolution)
7. feat — HTTP module (redirect chain, timing, security header audit)
8. feat — TLS module (stdlib `ssl`/`socket`)
9. feat — light tech fingerprinting
10. feat — JSON / Markdown / HTML reporting + coloured console
11. test — pytest suite, all network mocked, >= 80% coverage
12. ci — GitHub Actions (ruff + pytest + coverage, Python 3.10–3.12)
13. docs — ARCHITECTURE rewrite, sample output, v0.2.0 changelog + tag

## Environment notes

- Local interpreter is CPython 3.14; the package targets Python >= 3.10 and CI runs 3.10–3.12.
- The system interpreter is PEP 668 externally managed, so everything is installed into a
  project-local `.venv/` (`python -m venv .venv && .venv/bin/pip install -e ".[dev]"`).
- `crt.sh` can be slow and intermittently answers `502`; the subdomains module must degrade
  gracefully (it reports an `error` field) rather than raising.

## Blocked

_(nothing yet)_

## How to run everything

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

ruff check .
ruff format --check .
pytest -q
pytest --cov=reconx --cov-report=term-missing --cov-fail-under=80

reconx --version
reconx example.com                                  # console summary
reconx example.com --modules all --format json       # JSON on stdout
reconx example.com --modules dns,http --format md    # Markdown on stdout
reconx example.com --modules all -o report.json      # JSON to a file
```

Never commit generated reports (they are gitignored via `*report*.json` / `reconx-*.json`).
