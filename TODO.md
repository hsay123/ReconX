# TODO

Refactor plan for ReconX. One tick per commit; see NOTES.md for context.

## Plan (in progress)

- [x] 1. docs — replace the stale RupeeLink README with an accurate one
- [ ] 2. chore — pyproject.toml, requirements, .gitignore, ruff config, LICENSE
- [ ] 3. refactor — `reconx/` package, dict-returning modules, `ReconX.py` shim
- [ ] 4. feat — argparse CLI, domain normalisation/validation
- [ ] 5. feat — DNS module on dnspython, drop the broken `dig *.domain` call
- [ ] 6. feat — subdomain discovery (crt.sh + capped wordlist resolution)
- [ ] 7. feat — HTTP module (redirect chain, timing, security header audit)
- [ ] 8. feat — TLS module (stdlib ssl/socket)
- [ ] 9. feat — light tech fingerprinting
- [ ] 10. feat — JSON / Markdown / HTML reporting + coloured console output
- [ ] 11. test — pytest suite, network fully mocked, >= 80% coverage
- [ ] 12. ci — GitHub Actions (ruff + pytest + coverage, Python 3.10–3.12)
- [ ] 13. docs — ARCHITECTURE rewrite, sample output in assets/, v0.2.0 release

## Done previously

- [x] Initial prototype: `ReconX.py` with IP / headers / WHOIS / `dig` subdomain lookup
- [x] Project documentation scaffolding (ARCHITECTURE.md, CHANGELOG.md, DAILY_LOG.md)
