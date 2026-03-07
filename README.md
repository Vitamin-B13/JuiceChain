# JuiceChain

JuiceChain 是一个通用 Web 安全测试工具链，覆盖连通性探测、信息收集、攻击面枚举、漏洞验证与报告生成，适用于本地靶场、测试环境和授权目标。

## Features

- 统一 CLI 输出模型：所有命令返回一致的 `meta/ok/target/data/errors` 结构，便于自动化流水线消费。
- 流式 HTTP 读取：所有网络模块统一经由 `HttpClient`，支持 `max_bytes` 截断、防止大响应拖垮扫描进程。
- SPA 友好枚举：同时提取页面链接、表单、hash route、前端资产路由和 API 候选。
- SPA 降噪机制：目录爆破内置 fallback 探针，自动区分真实服务端端点与 SPA catch-all 噪声。
- 多阶段漏洞检测：反射型 XSS、错误型 SQLi、布尔型 SQLi（三次采样确认）与可选 DOM-XSS 浏览器验证。
- 可直接落地报告：从 `scan`/`vuln` 输出生成 Markdown/HTML 报告。

## Installation

```bash
git clone <your-repo-url>
cd JuiceChain
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux/macOS
# source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

可选 DOM-XSS 浏览器验证依赖：

```bash
pip install playwright
playwright install chromium
```

## Quick Check

```bash
juicechain --help
pytest -q --tb=short
ruff check
mypy --strict src
```

## Usage Demo

### 1) 目标扫描（scan）

```bash
juicechain scan -t http://127.0.0.1:3000 -o scan.json --pretty
```

示例输出（终端）：

```json
{
  "meta": {
    "tool": "juicechain",
    "version": "1.0.0",
    "command": "scan",
    "schema": "juicechain.cli.result/v1",
    "timestamp": 1772460000,
    "duration_ms": 1523
  },
  "ok": true,
  "target": "http://127.0.0.1:3000",
  "data": {
    "alive": {"alive": true, "status_code": 200},
    "info": {"homepage": {"status_code": 200, "title": "Juice Shop"}},
    "enum": {"crawler": {"pages_fetched": []}, "content_discovery": {}}
  },
  "errors": []
}
```

### 2) 漏洞验证（vuln）

```bash
juicechain vuln -i scan.json -o vuln.json
```

只提取输入点（不发主动探测请求）：

```bash
juicechain vuln -i scan.json --dry-run
```

启用 DOM-XSS 浏览器验证：

```bash
juicechain vuln -i scan.json --dom-xss
```

### 3) 报告生成（report）

```bash
juicechain report -i scan.json --vuln vuln.json --format html -o report.html
```

### 4) 一键流水线（pipeline）

```bash
juicechain pipeline -t http://127.0.0.1:3000 --format markdown -o report.md
```

## Vulnerability Plugins

`vuln` 模块已改为插件架构，运行时会自动发现并加载 `src/juicechain/plugins/` 下的插件（跳过 `base.py`、`loader.py`）。

- 内置插件：`XSS_REFLECTED`、`SQLI_ERROR`、`SQLI_BOOLEAN`、`AUTH_BYPASS`、`SQLI_TIME`、`OPEN_REDIRECT`、`PATH_TRAVERSAL`
- `DOM-XSS` 仍位于 `core/dom_xss.py`，仅在 `--dom-xss` / `enable_dom_xss=true` 时启用
- 插件按 `supported_locations` 过滤输入点，支持位置：`query`、`body_form`、`body_json`、`header`、`cookie`、`path_segment`
- 目前会为每个发现的 endpoint 额外生成 Header 注入点：`X-Forwarded-For`、`X-Forwarded-Host`、`Referer`、`User-Agent`

### Add a New Vulnerability Plugin

新增漏洞类型时不需要修改扫描主流程：

1. 在 `src/juicechain/plugins/` 新建一个 `.py` 文件
2. 定义 `class Plugin(VulnPlugin)` 并实现 `check(...) -> Finding | None`
3. 设置 `name`、`severity`（按需覆盖 `supported_locations`）

下次执行 `juicechain vuln ...` 时会自动加载新插件。
## Commands

- `alive`: 连通性检查（HEAD/GET 回退）
- `info`: 被动信息收集（标题、指纹、安全头、robots）
- `enum`: 攻击面枚举（爬虫 + 目录探测 + SPA 线索）
- `scan`: 执行 `alive -> info -> enum`
- `vuln`: 基于 scan 结果做漏洞验证（含可选 DOM-XSS）
- `report`: 生成 Markdown/HTML 报告
- `init`: 生成默认 TOML 配置
- `pipeline`: 端到端执行 `scan -> vuln -> report`

## Architecture

架构、模块依赖图、数据流和关键设计决策见：

- [docs/architecture.md](docs/architecture.md)

## Project Layout

- `src/juicechain/plugins/`: 漏洞检测插件（自动发现加载）
- `src/juicechain/core/input_point.py`: 通用输入点模型（含 header/cookie/path 等注入面）
- `src/juicechain/cli/`: 命令行入口与命令编排
- `src/juicechain/core/`: 核心扫描与漏洞模块
- `src/juicechain/utils/`: 日志与输出公共能力
- `tests/`: 测试用例
- `docs/`: 架构与设计文档

## Legal

仅在你明确授权的系统与环境中使用本工具。
