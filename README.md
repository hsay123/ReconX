# ReconX

> **Passive website reconnaissance CLI** — DNS, WHOIS, HTTP headers, TLS certificates, certificate transparency and light subdomain discovery, from one command.

ReconX is a small, dependency-light command line tool for **passive reconnaissance** against a single domain. It answers the questions you ask in the first ten minutes of an authorised assessment:

- What does this domain resolve to (A / AAAA / MX / NS / TXT / CNAME / SOA)?
- Who owns it (WHOIS / RDAP registration data)?
- What does the web server say (status, headers, redirect chain, response time, security headers)?
- What certificate is being served (issuer, SANs, expiry, protocol version)?
- What is it built with (light fingerprinting from headers and HTML meta tags)?
- What subdomains exist (certificate transparency logs + small wordlist resolution)?

---

> [!IMPORTANT]
> **Use ReconX only on domains you own or are explicitly authorised to test.**
> ReconX is a passive/low-intrusion information gathering tool. It performs public
> lookups (DNS, WHOIS, TLS handshake, ordinary HTTP `GET` requests, crt.sh).
> It contains no exploit code, no credential attacks and no port scanning.
> Unauthorised use may be illegal in your jurisdiction and can get you and your
> organisation in serious trouble.

---

## Installation

```bash
git clone https://github.com/hsay123/ReconX.git
cd ReconX

python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate

pip install -e .          # runtime deps
pip install -e ".[dev]"   # + ruff, pytest, pytest-cov (for development)
```

Requires **Python 3.10 or newer**. Runtime dependencies: `requests`, `dnspython`, `python-whois`, and `rich` (optional, for coloured console output).

Verify the install:

```bash
reconx --version
```

You can also run it without installing:

```bash
python -m reconx example.com
```

---

## Quick start

```bash
# Default modules (dns, http, tls, whois, tech) as a coloured console summary
reconx example.com

# Everything, machine readable, written to a file
reconx example.com --modules all --format json -o report.json

# Only the interesting bits
reconx example.com --modules dns,tls,subdomains

# A slower, wider subdomain sweep with your own wordlist
reconx example.com --modules subdomains --wordlist words.txt --concurrency 8 --timeout 20
```

---

## Usage

```
reconx [-h] [-m MODULES] [-f {text,json,md,html}] [-o OUTPUT] [-v]
       [--timeout TIMEOUT] [--concurrency CONCURRENCY] [--wordlist WORDLIST]
       [--version] target
```

| Option | Default | Description |
| --- | --- | --- |
| `target` | – | Domain to inspect, e.g. `example.com`. Scheme, port, path and `www.` are normalised away automatically. |
| `-m`, `--modules` | `dns,http,tls,whois,tech` | Comma separated list of modules, or `all`. |
| `-f`, `--format` | `text` | `text` (console summary), `json`, `md` (Markdown), `html` (self-contained report). |
| `-o`, `--output` | stdout | Write the report to a file instead of stdout. |
| `--timeout` | `10` | Per-request timeout in seconds (2–120). |
| `--concurrency` | `8` | Threads used for wordlist resolution (1–32). |
| `--wordlist` | bundled list | Path to a newline-delimited subdomain wordlist. |
| `-v`, `--verbose` | off | Show per-module errors and timing on stderr. |
| `--version` | – | Print the version and exit. |

### Modules

| Module | What it collects |
| --- | --- |
| `dns` | `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA` records via dnspython. |
| `http` | HTTPS-then-HTTP probe, redirect chain, status, response time, and a security header audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) with a pass/missing score. |
| `tls` | Certificate issuer, subject, SANs, validity window, days to expiry, negotiated protocol/cipher. |
| `whois` | Registrar, creation/expiry dates, name servers, status, registrant country. |
| `tech` | Light fingerprinting from headers and HTML meta/script signatures. |
| `subdomains` | Passive crt.sh lookups plus optional wordlist resolution, with wildcard detection and concurrency capping. |

Every module is isolated: if one fails (rate limited, unreachable, blocked), it reports an
`error` field and the remaining modules still run.

---

## Output

`--format json` emits a stable, machine-readable document:

```json
{
  "tool": "reconx",
  "version": "0.2.0",
  "target": "example.com",
  "generated_at": "2026-10-01T12:00:00+00:00",
  "duration_seconds": 1.842,
  "modules": ["dns", "http"],
  "results": {
    "dns": {
      "target": "example.com",
      "A": ["93.184.216.34"],
      "AAAA": [],
      "MX": [],
      "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
      "TXT": [],
      "CNAME": [],
      "SOA": null,
      "error": null
    },
    "http": { "...": "see --format json output" }
  },
  "errors": []
}
```

All lists are sorted and de-duplicated, so two runs against an unchanged target produce
byte-identical output apart from `generated_at` and `duration_seconds`.

`--format md` produces a Markdown report and `--format html` a single-file HTML report —
both suitable for attaching to a write-up.

---

## Responsible use

ReconX is intended for defensive security work, bug bounties and assessments you are
authorised to perform.

- It only reads public data and sends one ordinary `GET` per host.
- It does not scan ports, brute force credentials or attempt exploitation.
- Concurrency is capped (`--concurrency`) and every request has a timeout, so it will not
  flood a target.
- Please keep request volume low when scanning third-party infrastructure, and prefer the
  passive (`crt.sh`) subdomain source when you only need names.

---

## Development

```bash
pip install -e ".[dev]"

ruff check .
ruff format --check .
pytest -q                       # unit tests, fully mocked — no network access
pytest --cov=reconx --cov-report=term-missing
```

See [NOTES.md](NOTES.md) for the full command list, [ARCHITECTURE.md](ARCHITECTURE.md) for the
module design, and [CHANGELOG.md](CHANGELOG.md) for release history.

## Roadmap

- More output targets (CSV, SARIF).
- Optional JSON/YAML config files for recurring engagements.
- Deeper fingerprinting (JS library and analytics detection).
- Historical DNS / passive DNS enrichment.

See [TODO.md](TODO.md) for the working list.

---

## License

MIT — see [LICENSE](LICENSE).
