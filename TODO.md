# TODO

## v0.2.0 rebuild

- [x] 1. docs: Replace the stale RupeeLink README with an accurate ReconX README
- [x] 2. chore: pyproject.toml, console script, .gitignore, ruff config, LICENSE
- [x] 3. refactor: move to a `reconx/` package, functions return dicts
- [x] 4. feat: argparse CLI with domain normalization
- [x] 5. feat: DNS module on dnspython (drop the broken `dig *.domain` call)
- [x] 6. feat: subdomain discovery (crt.sh + capped wordlist resolution)
- [x] 7. feat: HTTP module with redirect chain and security-header audit
- [x] 8. feat: TLS module
- [x] 9. feat: lightweight technology fingerprinting
- [x] 10. feat: JSON / Markdown / HTML reporting and console summary
- [x] 11. test: mocked pytest suite, >= 80% coverage on the package
- [x] 12. ci: GitHub Actions (ruff + pytest + coverage, Python 3.10-3.12)
- [x] 13a. docs: rewrite ARCHITECTURE.md for the v0.2.0 package
- [ ] 13b. docs: refresh sample output, v0.2.0 release entry, tag

## Future ideas

- [ ] Custom DNS resolver selection (`--resolver`)
- [ ] Scan diffing: compare two runs and report infrastructure changes
- [ ] Richer fingerprint signatures with confidence scores
- [ ] Optional subdomain wordlist from a remote list, cached locally
- [ ] Machine-readable exit codes per module for scripted pipelines
- [ ] IPv6-aware subdomains and per-host TLS correlation
