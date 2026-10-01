# NOTES

## Baseline

- Baseline commit count at start of rewrite: **19** (`git rev-list --count HEAD`).
- Target: baseline + 11 = **30** commits minimum.
- Baseline HEAD: `8cdffda docs: update changelog`.

## How to run everything

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

ruff check .
ruff format --check .
pytest -q
pytest --cov=reconx --cov-report=term-missing

# end-to-end (real network, example.com only)
pip install -e .
reconx example.com --format json
```

## Blocked

(none yet)

## Notes

- `reconx example.com --modules dns,http,tls,subdomains --format json -o report.json`
  is the canonical invocation the project is built around.
- ReconX_Docs.docx is pre-existing and must not be edited or deleted.
