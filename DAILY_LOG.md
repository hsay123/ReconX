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
