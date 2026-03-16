# 🏗️ ReconX — Architecture

> A deep-dive into how ReconX is structured, how data flows through it, and what every component does.

---

## Table of Contents

- [Overview](#overview)
- [High-Level Architecture](#high-level-architecture)
- [Project Structure](#project-structure)
- [Component Breakdown](#component-breakdown)
  - [Entry Point & Orchestrator](#entry-point--orchestrator)
  - [Module: IP Resolver](#module-ip-resolver)
  - [Module: Header Fetcher](#module-header-fetcher)
  - [Module: WHOIS Lookup](#module-whois-lookup)
  - [Module: Subdomain Scanner](#module-subdomain-scanner)
- [Data Flow](#data-flow)
- [Dependency Map](#dependency-map)
- [Execution Lifecycle](#execution-lifecycle)
- [Design Decisions](#design-decisions)
- [Limitations & Extension Points](#limitations--extension-points)

---

## Overview

ReconX is a **single-file, sequential Python CLI tool**. It has no server, no database, no background workers. The entire execution happens synchronously in one process — the user provides a domain, four recon functions run one after another, and results are printed to stdout.

**Architecture style:** Procedural monolith (intentionally simple)  
**Execution model:** Sequential / synchronous  
**Interface:** CLI (stdin prompt → stdout output)  
**External calls:** DNS resolver, HTTP server, WHOIS server, system `dig` command  

---

## High-Level Architecture

```
┌─────────────┐          ┌──────────────────────────────────────────────┐
│   User      │  domain  │                 ReconX.py                    │
│   (CLI)     │ ──────►  │                                              │
└─────────────┘          │   ┌─────────────────────────────────────┐   │
                         │   │       Main Orchestrator (main())     │   │
                         │   └──────┬──────┬──────┬────────────────┘   │
                         │          │      │      │                     │
                         │   ┌──────▼─┐ ┌──▼───┐ ┌▼──────┐ ┌───────┐  │
                         │   │  IP    │ │ HDR  │ │ WHOIS │ │  DIG  │  │
                         │   │Resolve │ │Fetch │ │Lookup │ │ Scan  │  │
                         │   └──┬─────┘ └──┬───┘ └───┬───┘ └───┬───┘  │
                         │      │           │         │         │      │
                         │   ┌──▼───────────▼─────────▼─────────▼───┐  │
                         │   │         Output Collector              │  │
                         │   └──────────────────┬────────────────────┘  │
                         └──────────────────────┼──────────────────────┘
                                                │
                                                ▼
                                       Terminal (stdout)
```

---

## Project Structure

```
ReconX/
│
├── ReconX.py          # Entire application — all logic lives here
└── README.md          # Quick-start usage guide
```

ReconX is a **single-file application by design**. There are no packages, no submodules, no config files. This keeps setup friction at zero — clone and run.

---

## Component Breakdown

### Entry Point & Orchestrator

**Location:** `ReconX.py` → `main()` function (or top-level script execution)

The orchestrator:
1. Prompts the user for a domain via `input()`
2. Passes the domain sequentially to each recon module
3. Prints a section header before each module's output
4. Exits naturally after all four modules complete

```python
# Pseudocode flow
domain = input("Enter domain (example.com): ")

get_ip(domain)          # Module 1
get_headers(domain)     # Module 2
get_whois(domain)       # Module 3
get_subdomains(domain)  # Module 4
```

No return values are passed between modules — each function handles its own printing directly to stdout.

---

### Module: IP Resolver

**Purpose:** Resolve the domain to its IPv4 address.  
**Library:** Python stdlib `socket`  
**Function:** `socket.gethostbyname(domain)`

```
domain ──► socket.gethostbyname() ──► IPv4 string ──► print
```

**What it reveals:**
- The actual server IP (or CDN/proxy IP like Cloudflare's `104.x.x.x`)
- Whether the domain resolves at all (DNS failure = tool stops here)

**Error handling:** Wraps in try/except for `socket.gaierror` — prints an error message if DNS resolution fails.

---

### Module: Header Fetcher

**Purpose:** Send an HTTP GET request and display all response headers.  
**Library:** `requests` (pip)  
**Function:** `requests.get(f"http://{domain}")`

```
domain ──► requests.get() ──► response.headers dict ──► iterate & print
```

**What it reveals:**
- `Server:` — web server type (nginx, Apache, gws, etc.)
- `X-Powered-By:` — backend tech (PHP, Express, etc.)
- `Content-Type:` — MIME type of response
- Security headers (or lack of them): `X-Frame-Options`, `Strict-Transport-Security`, etc.

**Note:** Requests HTTP (port 80), not HTTPS. Some servers may redirect — `requests` follows redirects by default.

---

### Module: WHOIS Lookup

**Purpose:** Fetch domain registration metadata.  
**Library:** `python-whois` (pip)  
**Function:** `whois.whois(domain)`

```
domain ──► python-whois ──► WHOIS server (TCP 43) ──► parsed dict ──► print
```

**What it reveals:**
- Registrar name (e.g., MarkMonitor Inc., GoDaddy)
- `creation_date` — when the domain was first registered
- `expiration_date` — when the domain will expire (useful for hijack research)
- Name servers
- Registrant org (if not privacy-protected)

**Note:** Many modern domains use WHOIS privacy protection — registrant details will show the registrar's proxy, not the actual owner.

---

### Module: Subdomain Scanner

**Purpose:** Check for live subdomains using DNS queries.  
**Tool:** System `dig` command (from `dnsutils` package)  
**Method:** `subprocess` or `os.system()` to invoke `dig`

```
domain ──► dig {subdomain}.domain ──► DNS response ──► print if resolved
```

**Common subdomains checked:** `www`, `mail`, `ftp`, `admin`, `api`, `dev`, `staging`, `vpn`, `remote`

**What it reveals:**
- Additional attack surface (subdomains that resolve = live services)
- CDN/infrastructure patterns
- Internal service exposure (dev, staging, admin panels)

**Limitation:** This is a passive wordlist check, not a full brute-force. Only the default wordlist is checked — no custom wordlist support yet.

---

## Data Flow

```
User Input
    │
    │  "google.com"
    ▼
┌─────────────────────────┐
│  input() → domain str   │
└───────────┬─────────────┘
            │
    ┌───────▼────────────────────────────────────────┐
    │            Sequential Module Execution          │
    │                                                │
    │  1. socket.gethostbyname(domain)               │
    │     └─► Prints: [+] IP Address: x.x.x.x       │
    │                                                │
    │  2. requests.get("http://" + domain)           │
    │     └─► Prints: [+] Server Headers: ...       │
    │                                                │
    │  3. whois.whois(domain)                        │
    │     └─► Prints: [+] Whois Information: ...    │
    │                                                │
    │  4. subprocess/os → dig {sub}.domain           │
    │     └─► Prints: [+] Subdomain lookup: ...     │
    │                                                │
    └────────────────────────────────────────────────┘
            │
            ▼
     stdout (terminal)
```

All data flows **in one direction** — from the domain string, through each module, to stdout. There is no state shared between modules, no return values, no in-memory data accumulation.

---

## Dependency Map

| Module | Dependency | Type | Install |
|---|---|---|---|
| IP Resolver | `socket` | stdlib | Built-in |
| Header Fetcher | `requests` | pip | `pip install requests` |
| WHOIS Lookup | `python-whois` (`whois`) | pip | `pip install python-whois` |
| Subdomain Scanner | `dig` | system binary | `sudo apt install dnsutils` |

```
ReconX.py
├── import socket           ← stdlib, no install needed
├── import requests         ← pip install requests
├── import whois            ← pip install python-whois
└── os.system / subprocess  ← invokes `dig` system binary
                                └── requires: sudo apt install dnsutils
```

---

## Execution Lifecycle

```
$ python3 ReconX.py
         │
         ├─ 1. Script loads, imports validated
         │
         ├─ 2. Print banner: "===== Website Information Gatherer ====="
         │
         ├─ 3. input() → wait for user to type domain + Enter
         │
         ├─ 4. Module 1: IP Resolution
         │       ├─ Call socket.gethostbyname(domain)
         │       └─ Print result (or error)
         │
         ├─ 5. Module 2: Header Fetch
         │       ├─ HTTP GET to http://{domain}
         │       └─ Iterate response.headers, print each
         │
         ├─ 6. Module 3: WHOIS Lookup
         │       ├─ whois.whois(domain) → parsed object
         │       └─ Print registrar, dates, nameservers
         │
         ├─ 7. Module 4: Subdomain Scan
         │       ├─ For each subdomain in wordlist:
         │       │     └─ Run: dig {sub}.{domain} +short
         │       └─ Print subdomains that returned a DNS record
         │
         └─ 8. Script exits (process ends)
```

Total runtime: ~3–15 seconds depending on network latency and WHOIS server response time.

---

## Design Decisions

### Single-file architecture
**Why:** Zero setup overhead. A single `ReconX.py` is easy to clone, share, or run on any machine with Python. No package structure to navigate, no imports from local modules.

**Trade-off:** Everything is in one file, making it harder to unit-test individual modules or extend without touching the main script.

### Sequential execution (no async/threading)
**Why:** Simplicity. Each module's output is printed immediately — the user sees results as they come in, one section at a time.

**Trade-off:** Total runtime is the sum of all four module times. Async or threaded execution could run all four in parallel and finish ~4x faster.

### Print-to-stdout (no file output)
**Why:** Keeps the tool simple and composable — output can be piped (`python3 ReconX.py > results.txt`) using standard shell features.

**Trade-off:** No built-in structured export (JSON, HTML report). Parsing the output programmatically requires text processing.

### System `dig` for subdomain scanning
**Why:** `dig` is reliable, widely available on Linux, and already installed on Kali Linux by default. No need for a DNS library.

**Trade-off:** Not cross-platform (Windows requires WSL or manual install). A pure Python DNS library like `dnspython` would be more portable.

---

## Limitations & Extension Points

| Limitation | Potential Fix |
|---|---|
| Subdomain wordlist is small/hardcoded | Accept wordlist file as CLI argument |
| No output file export | Add `--output report.json` flag |
| Sequential execution is slow | Use `asyncio` or `ThreadPoolExecutor` |
| HTTP only (no HTTPS inspection) | Add TLS cert inspection via `ssl` module |
| No port scanning | Integrate `nmap` subprocess wrapper |
| Windows not supported | Replace `dig` with `dnspython` library |
| No rate limiting / stealth | Add random delays between requests |

---

## Extension Ideas (Future Architecture)

```
ReconX/
├── reconx/
│   ├── __init__.py
│   ├── cli.py              # argparse entry point
│   ├── modules/
│   │   ├── ip.py           # IP resolution
│   │   ├── headers.py      # HTTP header fetch
│   │   ├── whois.py        # WHOIS lookup
│   │   ├── subdomains.py   # DNS subdomain scan
│   │   └── ports.py        # (future) port scan
│   ├── output/
│   │   ├── terminal.py     # current: print to stdout
│   │   └── report.py       # (future) JSON/HTML export
│   └── utils/
│       └── validators.py   # domain input validation
└── tests/
    └── test_modules.py
```

---

*ReconX is intentionally minimal. The single-file design is a feature, not a limitation — it prioritizes zero-friction setup and readability over scalability.*

---

**Repo:** [github.com/hsay123/ReconX](https://github.com/hsay123/ReconX)  
**Author:** hsay123  
**License:** For authorized use only — see [README.md](./README.md#disclaimer)
