## Unreleased

- perf: modules now run on a bounded thread pool instead of one after another.
  Every module is a blocking network call, so a run used to cost the sum of
  all module latencies; it now costs about the slowest one. Results are
  assembled in selection order, so report output stays deterministic.
- feat: `--resolver ADDRESS` selects the nameserver to query (`1.1.1.1`, or
  `1.1.1.1#5353` for a non-standard port), for split-horizon and internal
  zones where the system resolver answers for a different network. An unusable
  address falls back to the system resolver instead of failing the module.
- fix: internationalized domains are encoded to punycode before validation, so
  `münchen.de` and `例え.テスト` are scanned instead of rejected as invalid.
- fix: the DNS sweep stops at the first NXDOMAIN. Each record type had been
  reporting the same NXDOMAIN independently, so a nonexistent domain cost
  seven identical queries and produced seven duplicate errors.
- fix: `--concurrency 0` (or a negative value) is now a usage error instead of
  being silently clamped to one thread and exiting 0.
- fix: the redirect walk stops as soon as a URL repeats and reports the cycle,
  rather than re-requesting seen URLs and ending with a bare "exceeded 5
  redirects".
- fix: a security header sent with an empty value is counted as missing. It
  protects nothing, and scoring it as present overstated the site's posture.
- fix: the crt.sh request now honours `--timeout` (scaled up, and still capped
  at 30s) instead of ignoring it and waiting a fixed 30 seconds.
- perf: subdomain resolution reuses one resolver per worker thread instead of
  building a new one for every candidate name.
- fix: the report renders safely when a module returns an unexpected shape;
  the tech section used to raise KeyError and lose the finished report.
- fix: the default `User-Agent` is derived from the packaged version instead of
  a hardcoded string that went stale on release.
- docs: added SECURITY.md stating the authorization policy and how to report a
  vulnerability in ReconX itself.

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
- feat: light technology fingerprinting from `Server` / `X-Powered-By` headers,
  the `generator` meta tag and script/link asset URLs. Matches carry a
  confidence level — `high` for something that names the technology outright,
  `low` for a filename that only suggests it.
- feat: reporting in four formats from one report dict — a `rich` console
  summary (plain-text fallback when `rich` is not installed), key-sorted JSON,
  Markdown, and a self-contained HTML page with inline CSS and escaped values.
  Nested records such as MX and SOA are flattened instead of printed as Python
  literals.
- test: 303 unit tests, all network access mocked, 97% branch coverage on the
  `reconx` package (floor set at 80%). A session fixture in `conftest.py`
  refuses outbound connections outright, so an unmocked call fails loudly
  instead of silently hitting the internet or making CI flaky.
- fix: `register_module` now actually registers. It appended to the module
  table, but the list used for lookup and `--help` was frozen at import, so a
  newly added module could never run.
- ci: GitHub Actions running ruff and pytest with coverage on Python 3.10–3.12,
  plus a job that builds the wheel, installs it into a clean environment and
  asserts the bundled wordlist survives packaging.
- fix(cli): accept `--max-workers` as an alias for `--concurrency` so the
  documented example works; fix the README default (8, not 10).
- feat(cli): add `--legal` to print the authorization notice and exit, and
  `--no-crtsh` (`ReconContext.no_crtsh`) to skip the slow transparency lookup
  for wordlist-only runs.
- fix(cli): `-o/--output` now creates missing parent directories.
- feat(report): dedicated WHOIS section with stable field order in
  text/Markdown/HTML; JSON unchanged.
- docs: rewrite ARCHITECTURE.md for the v0.2.0 package and fix the README
  project layout (`report.py`, `context.py`, `x509.py`, `wordlists/`).
- test: packaging regression test that the bundled wordlist exists and loads.
