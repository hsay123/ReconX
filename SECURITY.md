# Security Policy

## Scope

This policy covers **ReconX itself** — the code in this repository, the packaged
release, and anything it fetches on your behalf.

It does **not** cover reconnaissance performed *with* ReconX. Findings ReconX
reports about a third party's website are that owner's business, not a
vulnerability in this project. To report one, contact the owner of the affected
domain.

## Authorized use

ReconX performs passive reconnaissance. It only reads data that is already
publicly reachable: DNS records, WHOIS registrations, certificate transparency
logs, one HTTPS request per host, and one TLS handshake to port 443.

You may only run it against a domain you own or have explicit written
permission to assess. Running it against third-party infrastructure without
authorization may violate the CFAA, the Computer Misuse Act, and equivalent laws
in other jurisdictions. If you are unsure whether you have permission, ask
first, in writing, before scanning.

ReconX does not port scan, brute force credentials, send payloads, or attempt
authentication. Keep it that way: a wordlist of common subdomain labels is
reconnaissance, not an attack.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public
issue. Use GitHub's **Security → Report a vulnerability** button on this
repository, which opens a private advisory visible only to the maintainer.

Include, where possible:

- the ReconX version (`reconx --version`) and how you installed it,
- the exact command or API call that reproduced the problem,
- what you expected and what happened instead,
- any logs with `--verbose`, with the target domain redacted.

Please avoid running destructive or load-bearing proof-of-concept tests against
third-party infrastructure. Demonstrating the bug against a domain you control,
or with a mocked target, is usually enough.

## What to expect

- Acknowledgement within a few days.
- An assessment and, where the issue is accepted, a fix or a documented reason
  why it will not be fixed.
- Credit in the release notes and CHANGELOG if you want it.

## Supported versions

Fixes land on `main` and in the latest release. Older versions are not patched;
update before reporting something that may already be fixed.

## Hardening notes for operators

ReconX talks to untrusted networks on your behalf. A few things worth knowing:

- TLS verification is **disabled** when reading certificates, because a failing
  certificate is exactly what the TLS module exists to report. Treat the issuer,
  validity, and hostname fields as unverified claims and confirm them yourself.
- WHOIS data is whatever the registry's server returned. Registrant fields are
  self-reported and frequently redacted or fictional.
- Fingerprinted technologies carry a confidence label, and header-based
  fingerprints are trivially spoofable by a server that wants to hide.
- `--wordlist` and the crt.sh response are untrusted input. Report output is
  escaped for HTML and Markdown, but paste generated HTML into a report only if
  you trust the target's names.
