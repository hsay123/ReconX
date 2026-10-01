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
- feat: DNS module on dnspython covering A, AAAA, MX, NS, TXT, CNAME and SOA
  with per-query timeouts. Replaces `socket.gethostbyname` and drops the old
  `subprocess` call to `dig *.example.com`, which was never valid DNS and so
  silently found nothing.
- feat: modules now take a shared `ReconContext` (timeout, concurrency,
  wordlist) rather than bespoke arguments, so `--timeout` actually reaches the
  network layer.
- feat: subdomain discovery. Certificate transparency via crt.sh, plus optional
  wordlist resolution through a concurrency-capped thread pool. Results from
  both sources are deduplicated and sorted; wildcard DNS is detected with a
  random-label probe so a catch-all zone does not report every word as a hit.
  Ships a small default wordlist in the package.
- feat: HTTP module records the full redirect chain (each hop's URL, status and
  destination), response time, and an audit of HSTS, CSP, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy and Permissions-Policy with a
  pass/missing score and grade. Hops are capped so a redirect loop terminates.
- feat: TLS module reports issuer, subject, SANs, validity window, days to
  expiry and the negotiated protocol and cipher from a single handshake to
  port 443. Adds `reconx.x509`, a small DER reader, because `getpeercert()`
  returns nothing when verification is off and raises when it is on — which
  means a broken certificate, the interesting case, could not be reported.
  Only 443 is ever contacted.
