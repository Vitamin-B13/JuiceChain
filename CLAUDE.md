# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JuiceChain is a CLI-driven penetration testing automation toolchain targeting OWASP Juice Shop (authorized lab use only). It implements a sequential pipeline: **alive → info → enum → vuln → report**.

## Commands

### Install (editable + dev extras)
```bash
pip install -e ".[dev]"
```

### Run CLI
```bash
juicechain alive -t http://localhost:3000
juicechain info -t http://localhost:3000 --pretty
juicechain enum -t http://localhost:3000 --pretty
juicechain scan -t http://localhost:3000 -o scan.json --pretty
juicechain vuln -i scan.json --pretty
juicechain vuln -i scan.json --dry-run --pretty
juicechain report -i scan.json
```

### Tests
```bash
pytest                          # all tests
pytest tests/test_alive_http.py # single file
pytest -k "test_name"           # single test by name
```

### Lint / Type-check
```bash
ruff check src/ tests/
mypy src/
```

## Architecture

### Module Pipeline

All core logic lives in `src/juicechain/core/`. Each stage is a standalone function returning a plain `dict`:

| Module | Entry function | Stage |
|---|---|---|
| `target.py` | `normalize_target_base()` | URL normalization shared by all stages |
| `alive.py` | `check_http_alive()` | HEAD/GET liveness check |
| `info_gather.py` | `gather_info()` | Headers, title, robots.txt, security header audit |
| `enumeration.py` | `enumerate_attack_surface()` | Crawler + content discovery |
| `vulnerability.py` | `scan_vulnerabilities()` | Input point derivation + vuln checks |

`cli/main.py` wires these together via `argparse` subcommands. The `scan` command runs all four stages sequentially and merges their outputs into one JSON document. The `vuln` command reads that JSON to derive `InputPoint` objects.

### HTTP Layer

`HttpClient` (`core/http_client.py`) is the single HTTP abstraction used by every module. Key behaviors:
- Streaming reads with `max_bytes` truncation
- Optional retry with exponential backoff (`backoff * 2^attempt`)
- Optional rate limiting (`min_interval_ms`)
- `body_signature()` produces a SHA-1 body fingerprint used for SPA fallback detection

### SPA-Aware Enumeration (`enumeration.py`)

Juice Shop is an Angular SPA that returns HTTP 200 + `index.html` for all unknown paths (catch-all). The enumeration stage handles this with:
1. **Crawler** fetches pages and extracts JS asset URLs, hash routes (`#/...`), and API path candidates from JS bundles via regex (`_ANGULAR_ROUTE_PATH_RE`, `_API_CANDIDATE_RE`).
2. **SPA fallback detection** (`detect_spa_fallback`) sends a request to a random path (`/__juicechain_probe__/<token>`) to capture the fallback body signature.
3. **Content discovery** (`dir_bruteforce`) classifies each finding as `server_endpoint`, `spa_route`, or `fallback_noise` by comparing body signatures and matching against known SPA routes.

### Vulnerability Module (`vulnerability.py`)

`derive_input_points_from_scan()` converts a scan JSON doc into `InputPoint` dataclass instances (method, path, location, param). Sources:
- `enum.crawler.spa.api_candidates_from_assets` — query params parsed via `urlparse`
- Heuristic: `/rest/user/login` always gets POST JSON fields `email`/`password`
- Builtin: `/rest/products/search?q=` always included

Three checks run per input point:
- `check_reflected_xss` — GET query params only; flags literal `<script>` tag reflection in HTML responses
- `check_sqli_error` — pattern-matches SQL error strings; supports both query and JSON body injection
- `check_sqli_boolean` — restricted to `/rest/products/search?q`; compares item count (preferred) or response length between baseline and `' OR 1=1-- ` payloads

### JSON Output Schema

Every command outputs JSON with a `meta` envelope:
```json
{
  "meta": { "tool", "version", "timestamp", "duration_ms" },
  "target": "...",
  "<stage>": { ... }
}
```
`vuln` output adds `input_points` (summary stats), `findings` (list of `Finding.to_dict()`), and `errors`.

### Testing Conventions

Tests are in `tests/`. Network-dependent tests mock HTTP using monkeypatching or fixtures. Vulnerability check tests (`test_vulnerability_checks.py`, `test_vulnerability_boolean_sqli.py`, etc.) pass mock `HttpClient` or `HttpResponse` objects directly into check functions rather than going through the CLI.
