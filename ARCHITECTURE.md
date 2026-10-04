# ReconX — Architecture (v0.2.0)

> How the `reconx/` package is structured, how data flows, and why it is built this way.

## Overview

ReconX is a **passive reconnaissance CLI**. One command runs six independent
modules (DNS, WHOIS, HTTP, TLS, tech fingerprint, subdomains) and renders one
report dict as text, JSON, Markdown, or self-contained HTML.

Architecture style: modular monolith with error isolation.
Execution model: synchronous; only wordlist DNS resolution uses a capped thread pool.
Interface: `reconx` console script (`reconx/cli.py`) plus `python -m reconx`.

Legacy `ReconX.py` remains as a thin backward-compatible shim over the package.

## Project structure

```
reconx/
├── __init__.py       # version, public run()
├── __main__.py       # python -m reconx
├── cli.py            # argparse, domain normalization via core, --output, --legal
├── context.py        # ReconContext(timeout, concurrency, wordlist, no_crtsh)
├── core.py           # normalize_domain, module registry, run(), error isolation
├── dns_info.py       # dnspython: A/AAAA/MX/NS/TXT/CNAME/SOA
├── whois_info.py     # python-whois wrapper, flattened to JSON-safe dict
├── http_info.py      # HTTPS-first fetch, manual redirect chain, header audit
├── tls_info.py       # single handshake to :443, protocol/cipher/expiry
├── x509.py           # minimal DER reader (reports broken chains getpeercert hides)
├── fingerprint.py    # Server/X-Powered-By/generator/asset signatures + confidence
├── subdomains.py     # crt.sh + capped wordlist resolution, wildcard detection
├── report.py         # text/json/md/html renderers over one report dict
└── wordlists/
    └── default_subdomains.txt
tests/                # mocked pytest suite, no real network (conftest blocks sockets)
.github/workflows/ci.yml  # ruff + pytest/coverage on 3.10-3.12 + wheel install check
```

## Data flow

```
CLI input → core.normalize_domain → core.resolve_modules
  → core.run(domain, modules, context)
      → _run_one(name) per module, each try/except → {"error": ...} on failure
      → {"tool","version","target","generated_at","duration_seconds",
         "modules","results","summary"}
  → report.render(report, fmt) → stdout or -o PATH (parents created)
```

Modules share only `ReconContext`. They never call each other and never share
mutable state. `core._summarize` counts `modules_failed` and `warning_count`
for the console summary and HTML pills.

## Components

- **cli.py**: thin front end. Parses `--modules`, `--format`, `--timeout`,
  `--concurrency/--max-workers`, `--wordlist`, `--no-crtsh`, `-v`, `--legal`,
  `--version`, `-o`. Returns 0 on success, 2 on usage errors, 1 when every
  module failed.
- **context.py**: frozen `ReconContext`. `MAX_CONCURRENCY = 32` caps the
  wordlist pool; `no_crtsh` skips the slow transparency lookup.
- **core.py**: `normalize_domain` strips scheme/credentials/port/path, lowercases,
  validates labels. `available_modules` reads the live registry so
  `register_module` works. `resolve_modules` returns registry order for
  deterministic reports.
- **dns_info.py**: per-type dnspython queries with timeout; replaces the old
  `dig *.domain` subprocess call.
- **subdomains.py**: `query_crtsh` (30s timeout, never raises) plus
  `resolve_names` (ThreadPoolExecutor, clamped workers). `discover` dedupes,
  detects wildcard DNS via a random-label probe, and honors `no_crtsh`.
- **http_info.py**: tries HTTPS then HTTP, walks up to 5 redirects manually to
  record the chain, audits 6 security headers with score/grade.
- **tls_info.py + x509.py**: one handshake to port 443 only; reports issuer,
  subject, SANs, validity window, days-to-expiry, protocol, cipher.
- **report.py**: pure renderers. `_section_body` selects human-readable fields
  per module (full data stays in JSON); all HTML is escaped, CSS is inline.
- **fingerprint.py**: header/meta/asset matching with high/low confidence.

## Design decisions

- **Error isolation over fail-fast**: each module failure becomes an `error`
  string in its own result; the run always returns the other modules.
- **Passive sources only**: DNS, WHOIS, HTTP headers, TLS metadata, crt.sh.
  No port scanning, payloads, or auth. Timeouts and a tiny default wordlist
  keep runs polite.
- **Deterministic output**: sorted module order, sorted lists, key-sorted JSON,
  so diffing two runs shows infrastructure change, not rendering noise.
- **Optional `rich`**: colored console when installed, plain-text fallback
  otherwise, so the base install stays lean.
- **Tests block the network**: `conftest.py` refuses outbound connections, so
  unmocked calls fail loudly instead of making CI flaky.

## Extension points

- Custom DNS resolver (`--resolver`) — see TODO.
- Scan diffing: compare two JSON reports.
- Richer fingerprint signatures with confidence scoring.
