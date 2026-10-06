# ReconX

> Passive website reconnaissance CLI. One command, a full picture of a domain.

[![Python](https://img.shields.io/badge/python-3.10%2B-3178C6?style=flat-square&logo=python)](https://www.python.org)
[![Ruff](https://img.shields.io/badge/lint-ruff-000000?style=flat-square)](https://github.com/astral-sh/ruff)
[![Tests](https://img.shields.io/badge/tests-pytest-0A9EDC?style=flat-square&logo=pytest)](https://docs.pytest.org)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

ReconX collects publicly available information about a domain and prints it in a
form you can read, pipe, or commit. It is intentionally **passive**: it reads DNS
records, WHOIS, HTTP response headers, and certificate-transparency logs. It
does not exploit, brute-force, or scan.

```bash
reconx example.com --modules dns,http,tls,subdomains --format json -o report.json
```

---

## What it does

| Module | What you learn | Source |
| --- | --- | --- |
| `dns` | A / AAAA / MX / NS / TXT / CNAME / SOA records | dnspython |
| `whois` | Registrar, creation/expiry dates, nameservers, status | WHOIS servers |
| `http` | Status, redirect chain, timing, security-header audit | HTTPS then HTTP |
| `tls` | Issuer, subject, SANs, expiry countdown, protocol | TLS handshake |
| `tech` | Server/CMS/framework/CDN fingerprints | Response headers + HTML |
| `subdomains` | Discovered hostnames | crt.sh + wordlist DNS |

Every module is independent. If WHOIS times out, you still get your DNS, HTTP,
and TLS results — a failing module records an `error` field instead of aborting
the run.

---

## Install

Requires Python 3.10 or newer.

```bash
git clone https://github.com/hsay123/ReconX.git
cd ReconX

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -e .
```

Development install with the test and lint tooling:

```bash
pip install -e ".[dev]"
```

---

## Usage

```
reconx [OPTIONS] DOMAIN
```

| Option | Default | Description |
| --- | --- | --- |
| `DOMAIN` | required | Target domain, e.g. `example.com` |
| `-m, --modules` | all | Comma-separated subset of `dns,whois,http,tls,tech,subdomains` |
| `--timeout` | `10.0` | Per-request timeout in seconds |
| `--concurrency, --max-workers` | `8` | Threads used for wordlist resolution (minimum 1, capped at 32) |
| `--wordlist` | built-in | Path to a custom subdomain wordlist |
| `--resolver` | system | DNS server to query, e.g. `1.1.1.1` or `1.1.1.1#5353` |
| `--no-crtsh` | off | Skip the certificate-transparency lookup |
| `-f, --format` | `text` | Output format: `text`, `json`, `md`, `html` |
| `-o, --output` | stdout | Write the report to a file instead of stdout |
| `-v, --verbose` | off | Show warnings and per-module progress on stderr |
| `--version` | | Print the version and exit |
| `--legal` | | Print the authorization notice and exit |

The domain is normalized for you, so `https://www.example.com/path?q=1`,
`www.example.com` and `example.com` are all accepted and reduced to a clean
registrable-looking hostname. Internationalized names are encoded to punycode,
so `münchen.de` is scanned as `xn--mnchen-3ya.de`.

Modules are independent network calls, so they are dispatched concurrently and
a run costs roughly as long as its slowest module rather than the sum of all of
them. Results are still reported in a fixed order, so two runs against an
unchanged target produce identical output apart from the timestamp.

### Examples

Everything, human-readable:

```bash
reconx example.com
```

Just DNS and TLS, as JSON:

```bash
reconx example.com --modules dns,tls --format json
```

Markdown for a report, with a slower timeout for a slow target:

```bash
reconx example.com --format md --timeout 20 -o recon.md
```

Self-contained HTML you can open or email:

```bash
reconx example.com --format html -o report.html
```

Subdomain discovery with your own wordlist and a conservative concurrency cap:

```bash
reconx example.com --modules subdomains --wordlist words.txt --max-workers 5
```

Pin DNS to a specific nameserver, for split-horizon or internal zones:

```bash
reconx corp.example --resolver 10.0.0.53
```

### Sample output

```text
============================================================
 ReconX 0.2.0 - passive recon for example.com
 2026-10-01T23:10:04Z - 4 modules - 2.31s
============================================================

DNS
  A       93.184.216.34
  AAAA    2606:2800:220:1:248:1893:25c8:1946
  MX      10 mail.example.com  (pref 10)
  NS      a.iana-servers.net
  TXT     v=spf1 -all

HTTP
  URL         https://example.com
  Status      200 OK
  Time        184 ms
  Redirects   0
  Headers     12 items
  Security    4/6 present  [!] content-security-policy, permissions-policy

TLS
  Issuer     DigiCert Inc - DigiCert TLS RSA SHA256 2020 CA1
  Subject    CN=example.com
  Expires    2026-11-24 (54 days)
  Protocol   TLSv1.3

TECH
  Server        gws
  Generator     (none)
  Detected      gws, nginx

SUBDOMAINS
  crt.sh        3 names
  wordlist      2 resolved / 40 tried
  Total         5
    example.com
    mail.example.com
    www.example.com

============================================================
 Done in 2.31s - 5 subdomains - 2 warnings
 Full JSON report: reconx example.com --format json
============================================================
```

---

## Safety and scope

> **Use ReconX only on domains you own or are explicitly authorized to test.**
> Unauthorized reconnaissance can be unlawful in many jurisdictions.

The design enforces that boundary:

- **Passive sources only.** DNS, WHOIS, TLS handshake metadata, HTTP headers, and
  the public crt.sh transparency log. Nothing is exploited or authenticated.
- **No port scanning, no payloads, no credential testing.** There is no such code
  in this repository.
- **Bounded work.** Every network call has a timeout, wordlist resolution uses a
  thread pool with a hard concurrency cap, and requests carry a descriptive
  user-agent.
- **Small default wordlist.** A few dozen common hostnames, not an aggressive
  brute-force list.

Run `reconx --legal` to print the notice.

## Development

```bash
pip install -e ".[dev]"

ruff check .                 # lint
ruff format --check .        # formatting
pytest -q                   # tests (all network access is mocked)
pytest --cov=reconx          # coverage
```

The test suite never touches the network: DNS, WHOIS, and HTTP are mocked, so
`pytest` is safe to run offline and in CI.

## Project layout

```
reconx/
├── __init__.py       # version, public run() entry point
├── __main__.py       # python -m reconx shim
├── cli.py            # argparse front end (--legal, --no-crtsh, -o creates dirs)
├── context.py        # ReconContext: timeout, concurrency, wordlist, no_crtsh
├── core.py           # orchestration, error isolation
├── dns_info.py       # DNS records
├── whois_info.py     # WHOIS
├── http_info.py      # HTTP + security headers
├── tls_info.py       # TLS certificate
├── x509.py           # minimal DER reader for broken-chain reporting
├── fingerprint.py    # technology detection
├── subdomains.py     # crt.sh + wordlist
├── report.py         # text / json / md / html renderers
└── wordlists/
    └── default_subdomains.txt  # bundled subdomain wordlist
```

## Roadmap

- [x] CLI, modular architecture, JSON/Markdown/HTML reports
- [x] DNS, WHOIS, HTTP, TLS, fingerprint, subdomain modules
- [x] Mocked test suite and CI
- [ ] More fingerprint signatures and confidence scoring
- [ ] Optional custom DNS resolver selection
- [ ] Diff two scans to spot infrastructure changes over time

See [TODO.md](TODO.md) for the full list and [ARCHITECTURE.md](ARCHITECTURE.md)
for design detail.

## License

MIT. See [LICENSE](LICENSE).
