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
