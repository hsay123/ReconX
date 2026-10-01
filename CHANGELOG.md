# Changelog

All notable changes to ReconX are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **README rewritten.** The previous README described an unrelated project (RupeeLink) and
  was actively misleading. It now documents what ReconX actually does, how to install it,
  the modules, the legal notice and the roadmap.

## [0.1.0]

- Initial single-file prototype: IP lookup, header fetch, WHOIS and a `subprocess` call to
  `dig *.example.com` (which never finds anything — see the refactor notes).
