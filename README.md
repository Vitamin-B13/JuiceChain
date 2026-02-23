# JuiceChain

A penetration testing automation toolchain for OWASP Juice Shop (for learning + portfolio).

## Goals
- Engineering-focused pentest workflow automation
- CLI-driven toolchain
- Target: OWASP Juice Shop

## Quick Start (WIP)
- Python + conda environment
- Run CLI help (coming soon)

## Project Status
- v0.1: project scaffold in progress

## Structure
- src/juicechain: main package
  - cli/: CLI entry and commands
  - core/: core pipeline modules
  - utils/: helpers
- tests/: unit tests
- docs/: design docs

## CLI

### alive
Check whether a target is reachable via HTTP and output JSON.

```bash
juicechain alive -t http://localhost:3000
juicechain alive -t http://localhost:3000 --timeout 2


### info
Passive info gathering: homepage headers, page title, and robots.txt.

```bash
juicechain info -t http://localhost:3000
juicechain info -t 192.168.204.24:3000 --pretty

### enum
Attack surface enumeration: crawler (internal links/forms/params) + content discovery (small wordlist).

```bash
juicechain enum -t 192.168.204.24:3000 --pretty

用法示例：juicechain enum -t 192.168.204.24:3000 --pretty

说明：Juice Shop 是 SPA，很多不存在路径会返回 200（前端兜底 index.html），所以需要结合响应体特征判断真假资源；当前版本先记录为“发现项”，后续 v0.5 做降噪。