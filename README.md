# JuiceChain

JuiceChain 是一个面向授权目标的轻量化安全测试工具链，聚焦于侦察、信息收集、攻击面枚举与基础漏洞检测（适合 OWASP Juice Shop 等实验环境）。

## 当前里程碑

- `v0.6`：日志与输出格式统一（统一 schema、统一日志风格、统一错误处理）。

## 功能概览

- `alive`：HTTP 连通性探测
- `info`：被动信息收集（首页/指纹/安全头/robots）
- `enum`：攻击面枚举（爬虫 + 内容发现 + SPA 路由/接口线索）
- `scan`：一键流水线（`alive -> info -> enum`）
- `vuln`：输入点提取与漏洞检测（SQLi/XSS，支持可选 DOM-XSS 浏览器验证）
- `report`：从 `scan` 结果生成 Markdown 报告

## 环境要求

- Python `>= 3.10`
- 推荐：`pip` 最新版
- 操作系统：Windows / Linux / macOS

## 安装说明

### 方式一：开发模式安装（推荐）

```bash
git clone <你的仓库地址>
cd JuiceChain

# 建议使用虚拟环境
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1

# Linux/macOS
# source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### 方式二：仅运行最小依赖

```bash
pip install -e .
```

### 可选：启用 DOM-XSS 浏览器验证

`vuln --dom-xss` 依赖 Playwright 浏览器组件：

```bash
pip install playwright
playwright install chromium
```

## 快速自检

```bash
juicechain --help
pytest -q
```

## v0.6 统一输出与日志

### 统一输出 schema

所有命令输出统一为以下顶层结构（默认 `json`）：

```json
{
  "meta": {
    "tool": "juicechain",
    "version": "0.x.x",
    "command": "scan",
    "schema": "juicechain.cli.result/v1",
    "timestamp": 1700000000,
    "duration_ms": 1234
  },
  "ok": true,
  "target": "http://127.0.0.1:3000",
  "data": {},
  "errors": []
}
```

### 输出格式切换

- `--format json|table`：控制终端展示格式（默认 `json`）
- `--pretty`：JSON 美化输出
- `scan`、`vuln` 支持 `-o/--output` 将统一 JSON 结果写入文件

### 日志系统

- 默认日志文件：`.juicechain/juicechain.log`
- 日志格式：`时间 | 级别 | 模块 | 消息`
- 参数：
  - `--log-level DEBUG|INFO|WARNING|ERROR|CRITICAL`
  - `--log-file <path>`
  - `--no-log-file`（只输出控制台日志）

## 完整用法示例

### 1. 连通性探测（alive）

```bash
juicechain alive -t http://127.0.0.1:3000
juicechain alive -t 127.0.0.1:3000 --timeout 2 --format table
juicechain alive -t http://127.0.0.1:3000 --follow-redirects --log-level DEBUG
```

### 2. 被动信息收集（info）

```bash
juicechain info -t http://127.0.0.1:3000
juicechain info -t 127.0.0.1:3000 --max-bytes 300000 --pretty
juicechain info -t 127.0.0.1:3000 --insecure --format table
```

### 3. 攻击面枚举（enum）

```bash
juicechain enum -t 127.0.0.1:3000
juicechain enum -t 127.0.0.1:3000 --max-pages 50 --rate-limit-ms 100 --format table
juicechain enum -t 127.0.0.1:3000 --wordlist custom_wordlist.txt --no-spa-assets
```

### 4. 一键流水线扫描（scan）

```bash
juicechain scan -t 127.0.0.1:3000
juicechain scan -t 127.0.0.1:3000 --pretty -o scan.json
juicechain scan -t 127.0.0.1:3000 --format table --log-file logs/scan.log
```

### 5. 漏洞扫描（vuln）

```bash
# 基于 scan 输出进行 dry-run（仅提取输入点）
juicechain vuln -i scan.json --dry-run --pretty

# 执行漏洞检测
juicechain vuln -i scan.json --timeout 5 --retries 1 -o vuln.json

# 启用 DOM-XSS 浏览器验证（可选）
juicechain vuln -i scan.json --dom-xss

# 浏览器有头模式（调试）
juicechain vuln -i scan.json --dom-xss --headed
```

> `vuln` 的输入同时兼容：
> 1) 旧版 `scan.json`（包含 `alive/info/enum`）  
> 2) v0.6 统一输出结构（`meta + data`）

### 6. 生成报告（report）

```bash
juicechain report -i scan.json
juicechain report -i scan.json -o report.md
juicechain report -i scan.json --format table
```

## 项目结构

- `src/juicechain/cli/`：CLI 入口与命令编排
- `src/juicechain/core/`：核心探测/扫描模块
- `src/juicechain/utils/`：公共能力（日志、输出格式等）
- `tests/`：单元测试
- `docs/`：架构与设计文档

## 免责声明

仅可用于你有明确授权的目标环境。禁止对未授权系统执行扫描与测试行为。
