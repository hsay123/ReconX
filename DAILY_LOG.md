## 2026-07-20
- Daily maintenance.
## 2026-08-15
- Daily maintenance.
## 2026-10-01
- Started the v0.2.0 rebuild. Recorded baseline (19 commits) in NOTES.md.
- Step 1: rewrote README.md — it described RupeeLink, not ReconX. Now documents
  the real CLI: six passive modules, install steps, option table, sample output,
  authorization notice, and roadmap.
- Step 2: added pyproject.toml, requirements files, .gitignore, ruff config and
  MIT LICENSE so the project is installable and lintable.
- Step 3: split ReconX.py into a `reconx/` package. `core.py` owns domain
  normalization, the module registry and the run loop; `dns_info`, `http_info`
  and `whois_info` return dicts and report failures as an `error` key.
  `ReconX.py` stays as a shim over the old function names. Added the first unit
  tests for `core` (27 passing, no network access).
- Step 4: added `reconx/cli.py` and `python -m reconx`. Domain normalization
  strips scheme/port/path and rejects junk with exit code 2; JSON output is
  sorted and machine readable. 44 tests passing. Verified `reconx example.com
  --modules dns --format json` end to end.
- Step 5: replaced the stdlib `socket` resolver with dnspython and dropped the
  `subprocess` `dig *.domain` call, which was not valid DNS and never returned
  anything. A/AAAA/MX/NS/TXT/CNAME/SOA now come back structured, with NXDOMAIN
  and timeouts distinguished in the error text. Added `ReconContext` so
  `--timeout`, `--concurrency` and `--wordlist` actually reach the modules
  instead of being parsed and ignored. 60 tests passing.
- Step 6: added `reconx/subdomains.py`. crt.sh certificate transparency for
  passive discovery, plus wordlist resolution capped at 32 threads with a
  per-query lifetime. Wildcard DNS is detected with a random-label probe,
  because a catch-all zone would otherwise report every word in the list as a
  hit — the single most common way subdomain tools produce garbage. crt.sh was
  answering 502 from this network all session, which exercised the degradation
  path: the module reports a warning and still returns wordlist results.
  93 tests passing.
- Step 7: HTTP module now walks the redirect chain manually (bounded at 5 hops,
  so a redirect loop terminates) and reports every hop instead of only the
  final destination. Added a security-header audit for HSTS, CSP,
  X-Frame-Options, X-Content-Type-Options, Referrer-Policy and
  Permissions-Policy, with a score and grade. 123 tests passing.
- Step 8: added the TLS module. It reads issuer, subject, SANs, validity and
  the negotiated protocol/cipher from one handshake on port 443 — no port
  scanning. Getting the fields out of a certificate that does not validate
  needed a small DER reader (`reconx/x509.py`): `getpeercert()` returns `{}`
  under `CERT_NONE` and raises under a verifying handshake, so both paths fail
  to report the expired/self-signed certificates that actually matter.
  Checked a real example.com certificate in as a DER fixture rather than
  hand-rolling DER bytes, so the parser is tested against real ASN.1
  (multi-byte OIDs, long-form lengths, UTCTime). 163 tests passing.
- Step 9: added the `tech` module — fingerprinting from `Server` and
  `X-Powered-By`, the `generator` meta tag, and script/link asset URLs. Each
  match carries high/low confidence so a `jquery` substring in a filename is
  not presented as fact. 187 tests passing.
- Step 10: added `reconx/report.py` with four renderers over the same report
  dict — rich console (plain-text fallback), key-sorted JSON, Markdown, and a
  single-file HTML report with inline CSS and escaped values. Two bugs caught
  by running it against real output rather than fixtures: the rich console
  wrote to stdout *and* returned its text, so every report printed twice; and
  MX/SOA records rendered as Python dict literals in the Markdown and console
  views. 227 tests passing.
