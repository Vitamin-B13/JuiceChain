# JuiceChain

JuiceChain 是一个面向授权目标的轻量化安全测试工具链，覆盖连通性探测、被动信息收集、攻击面枚举和基础漏洞检测。

## 里程碑

- `v0.6`：统一日志与统一输出格式（JSON schema / 表格展示 / 一致化错误处理）

## 功能列表

- `alive`：检查目标是否可达
- `info`：抓取目标基础信息（标题、指纹、安全头、robots）
- `enum`：枚举攻击面（爬虫 + 目录探测 + SPA 线索）
- `scan`：一键执行 `alive -> info -> enum`
- `vuln`：基于 `scan` 结果做漏洞检测（含可选 DOM-XSS 浏览器验证）
- `report`：从 `scan` 结果生成 Markdown 报告

## 环境要求

- Python `>= 3.10`
- 推荐使用虚拟环境
- 推荐安装 `dev` 依赖用于测试与开发

## 安装（傻瓜式）

### 方式 A：开发安装（推荐）

```bash
git clone <你的仓库地址>                 # 1) 克隆项目
cd JuiceChain                             # 2) 进入项目目录
python -m venv .venv                     # 3) 创建虚拟环境

.venv\Scripts\Activate.ps1               # 4) Windows PowerShell 激活
# source .venv/bin/activate              # 4) Linux/macOS 激活

python -m pip install --upgrade pip      # 5) 更新 pip
pip install -e ".[dev]"                  # 6) 安装项目与开发依赖
```

### 方式 B：只运行（最小依赖）

```bash
pip install -e .                         # 仅安装运行依赖
```

### 可选：启用 DOM-XSS 浏览器检测

```bash
pip install playwright                   # 安装 Playwright Python 包
playwright install chromium              # 安装 Chromium 浏览器内核
```

## 先做一次自检

```bash
juicechain --help                        # 查看命令是否可用
pytest -q                                # 运行测试确认环境正常
```

## 输出与日志（v0.6）

### 统一输出 schema

所有命令都输出统一顶层结构：

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

### 输出控制参数

- `--format json|table`：终端输出格式（默认 `json`）
- `--pretty`：终端 JSON 美化显示
- `-o/--output`：写入结果文件（`scan` 和 `vuln` 支持）
  - 现在 `-o` 写出的 JSON 默认就是格式化（带缩进），便于阅读

### 日志参数

- 默认日志文件：`.juicechain/juicechain.log`
- `--log-level DEBUG|INFO|WARNING|ERROR|CRITICAL`
- `--log-file <path>`
- `--no-log-file`：只输出控制台日志，不写文件

## 命令完整示例（每条都带注释）

### 1) alive

```bash
juicechain alive -t http://127.0.0.1:3000                     # 基础可达性检查
juicechain alive -t 127.0.0.1:3000 --timeout 2               # 指定超时时间
juicechain alive -t 127.0.0.1:3000 --format table            # 表格形式显示结果
juicechain alive -t 127.0.0.1:3000 --log-level DEBUG         # 打开调试日志
```

### 2) info

```bash
juicechain info -t http://127.0.0.1:3000                      # 被动信息收集
juicechain info -t 127.0.0.1:3000 --max-bytes 300000          # 调整响应读取上限
juicechain info -t 127.0.0.1:3000 --follow-redirects          # 允许跟随跳转
juicechain info -t 127.0.0.1:3000 --format table              # 以表格展示摘要
```

### 3) enum

```bash
juicechain enum -t 127.0.0.1:3000                             # 默认攻击面枚举
juicechain enum -t 127.0.0.1:3000 --max-pages 50              # 增加爬虫最大页面数
juicechain enum -t 127.0.0.1:3000 --rate-limit-ms 100         # 设置请求间隔（毫秒）
juicechain enum -t 127.0.0.1:3000 --wordlist custom.txt       # 使用自定义字典
juicechain enum -t 127.0.0.1:3000 --no-spa-assets             # 禁止抓取 SPA 资源
```

### 4) scan

```bash
juicechain scan -t 127.0.0.1:3000                             # 一键跑完整流水线
juicechain scan -t 127.0.0.1:3000 --pretty                    # 终端美化 JSON
juicechain scan -t 127.0.0.1:3000 -o scan.json                # 输出到文件（自动格式化）
juicechain scan -t 127.0.0.1:3000 --format table              # 终端表格摘要
juicechain scan -t 127.0.0.1:3000 --log-file logs/scan.log    # 自定义日志文件位置
```

### 5) vuln

```bash
juicechain vuln -i scan.json --dry-run                         # 只提取输入点，不发检测请求
juicechain vuln -i scan.json --timeout 5 --retries 1          # 执行漏洞检测并调整超时/重试
juicechain vuln -i scan.json -o vuln.json                     # 输出到文件（自动格式化）
juicechain vuln -i scan.json --dom-xss                        # 开启 DOM-XSS 浏览器验证
juicechain vuln -i scan.json --dom-xss --headed               # 浏览器有头模式（调试）
juicechain vuln -i scan.json --format table                   # 表格展示漏洞摘要
```

> `vuln -i` 支持两种输入：
> 1. 旧版 `scan.json`（顶层有 `alive/info/enum`）  
> 2. v0.6 统一输出结构（`meta + data`）

### 6) report

```bash
juicechain report -i scan.json                                 # 输出 Markdown 到终端
juicechain report -i scan.json -o report.md                    # 写入 Markdown 报告文件
juicechain report -i scan.json --format table                  # 终端显示执行摘要表
```

## 真正新手操作清单（从 0 到 1）

1. 安装 Python 3.10+。  
2. 克隆仓库并进入目录。  
3. 创建并激活虚拟环境。  
4. 执行 `pip install -e ".[dev]"`。  
5. 执行 `juicechain --help` 确认命令可用。  
6. 执行 `juicechain scan -t http://127.0.0.1:3000 -o scan.json`。  
7. 打开 `scan.json` 查看结果（已是格式化 JSON）。  
8. 执行 `juicechain vuln -i scan.json -o vuln.json`。  
9. （可选）执行 `juicechain report -i scan.json -o report.md` 生成报告。  
10. 查看 `.juicechain/juicechain.log` 追踪完整过程日志。  

## 目录结构

- `src/juicechain/cli/`：CLI 入口
- `src/juicechain/core/`：核心探测/枚举/漏洞模块
- `src/juicechain/utils/`：日志与输出等通用能力
- `tests/`：单元测试
- `docs/`：架构文档

## 免责声明

仅可用于你明确授权的目标环境。禁止对未授权系统进行扫描与测试。
