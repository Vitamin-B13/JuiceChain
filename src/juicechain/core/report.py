from __future__ import annotations

import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Mapping
from urllib.parse import urlparse

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_RECOMMENDATION_MAP = {
    "XSS": "启用严格输出编码并按上下文转义（HTML/属性/JS），同时部署 CSP 限制脚本执行来源。",
    "SQLI": "所有数据库访问使用参数化查询或 ORM 绑定变量，禁止字符串拼接 SQL。",
    "CSRF": "对敏感操作启用 CSRF Token 并校验 Origin/Referer，Cookie 设置 SameSite。",
    "SSRF": "对目标地址做白名单校验，禁止访问内网/元数据地址并限制协议。",
    "RCE": "移除命令拼接，改用安全 API，最小化运行权限并隔离执行环境。",
}


def build_scan_report(scan_data: Mapping[str, Any], vuln_data: Mapping[str, Any] | None = None) -> str:
    """Build a Markdown report from scan and optional vulnerability payloads.

    Args:
        scan_data: `scan` command payload (legacy or unified schema).
        vuln_data: Optional `vuln` command payload.

    Returns:
        Markdown report text.
    """
    scan_meta, scan_doc = _extract_scan_context(scan_data)
    vuln_doc = _extract_vuln_context(vuln_data)

    findings = _as_list(vuln_doc.get("findings"))
    severity = _severity_counts(findings)

    target = _safe_str(scan_doc.get("target")) or _safe_str(scan_meta.get("target")) or "unknown"
    scan_time = _format_timestamp(scan_meta.get("timestamp"))
    tool_version = _safe_str(scan_meta.get("version")) or "unknown"

    alive = _as_dict(scan_doc.get("alive"))
    info = _as_dict(scan_doc.get("info"))
    enum = _as_dict(scan_doc.get("enum"))

    homepage = _as_dict(info.get("homepage"))
    fingerprint = _as_dict(info.get("fingerprint"))
    security_headers = _as_dict(info.get("security_headers"))

    crawler = _as_dict(enum.get("crawler"))
    spa = _as_dict(crawler.get("spa"))
    content_discovery = _as_dict(enum.get("content_discovery"))

    pages = _as_list(crawler.get("pages_fetched"))
    routes = _as_str_list(spa.get("routes_from_assets"))
    api_candidates = _as_str_list(spa.get("api_candidates_from_assets"))
    server_endpoints = _as_list(content_discovery.get("findings_server_endpoints"))
    spa_routes = _as_list(content_discovery.get("findings_spa_routes"))
    fallback_noise = _as_list(content_discovery.get("findings_fallback_noise"))

    lines: list[str] = []
    lines.append("# JuiceChain 渗透测试报告")
    lines.append("")
    lines.append("## 1. 概要")
    lines.append(f"- 目标：{target}")
    lines.append(f"- 扫描时间：{scan_time}")
    lines.append(f"- 工具版本：{tool_version}")
    lines.append(
        "- 结果摘要："
        f"{severity['high']} 个高危 / {severity['medium']} 个中危 / {severity['low']} 个低危"
    )
    if vuln_data is None:
        lines.append("- 漏洞数据：未提供（仅展示 scan 阶段结果）")
    lines.append("")

    lines.append("## 2. 目标信息")
    lines.append(
        "- 存活状态："
        f"{_safe_str(alive.get('alive')) or 'unknown'}，"
        f"响应时间：{_safe_str(alive.get('response_time_ms')) or 'unknown'} ms"
    )
    lines.append(
        "- 技术指纹："
        f"服务器={_safe_str(fingerprint.get('server')) or 'unknown'}，"
        f"框架={_safe_str(fingerprint.get('x_powered_by')) or 'unknown'}，"
        f"hints={_safe_json_like(fingerprint.get('hints'))}"
    )
    lines.append(
        "- 安全头审计："
        f"缺失={_safe_json_like(security_headers.get('missing'))}；"
        f"已存在={_safe_json_like(security_headers.get('present'))}；"
        f"过时头={_safe_json_like(security_headers.get('deprecated_present'))}"
    )
    if homepage:
        lines.append(
            f"- 首页：{_safe_str(homepage.get('url')) or 'unknown'} "
            f"(状态码={_safe_str(homepage.get('status_code')) or 'unknown'})"
        )
    lines.append("")

    lines.append("## 3. 攻击面")
    lines.append(f"- 发现页面数量：{len(pages)}")
    lines.append(f"- SPA 路由数量：{len(routes)}")
    lines.append(f"- API 端点数量：{len(api_candidates)}")
    lines.append(
        "- 分类统计："
        f"服务器端点={len(server_endpoints)} / "
        f"SPA 路由={len(spa_routes)} / "
        f"噪声={len(fallback_noise)}"
    )
    lines.append("")
    lines.append("### SPA 路由列表")
    lines.extend(_markdown_bullets(routes, fallback="- 未发现 SPA 路由"))
    lines.append("")
    lines.append("### API 端点列表")
    lines.extend(_markdown_bullets(api_candidates, fallback="- 未发现 API 端点"))
    lines.append("")

    if vuln_data is not None:
        lines.append("## 4. 漏洞发现")
        if findings:
            lines.append("")
            lines.append("| 严重程度 | 类型 | 路径 | 参数 | Payload | 证据 | 响应状态码 |")
            lines.append("| --- | --- | --- | --- | --- | --- | --- |")
            for finding in _sort_findings(findings):
                request = _as_dict(finding.get("request"))
                response = _as_dict(finding.get("response"))
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _md_cell(_safe_str(finding.get("severity"))),
                            _md_cell(_safe_str(finding.get("type"))),
                            _md_cell(_finding_path(request)),
                            _md_cell(_safe_str(request.get("param"))),
                            _md_cell(_safe_str(request.get("payload"))),
                            _md_cell(_safe_str(finding.get("evidence"))),
                            _md_cell(_safe_str(response.get("status_code"))),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("")
            lines.append("- 未发现漏洞。")
        lines.append("")

    lines.append("## 5. 建议")
    for rec in _build_recommendations(findings):
        lines.append(f"- {rec}")

    return "\n".join(lines)


def markdown_to_html(markdown: str) -> str:
    """Render report Markdown into a standalone HTML document.

    Args:
        markdown: Markdown content generated by `build_scan_report`.

    Returns:
        Full HTML page string.
    """
    body = _render_markdown_body(markdown)
    css = """
body {
  margin: 0;
  background: #f7f9fc;
  color: #16202a;
  font-family: "Segoe UI", "Helvetica Neue", sans-serif;
}
main {
  max-width: 960px;
  margin: 28px auto;
  background: #ffffff;
  border: 1px solid #d9e2ec;
  border-radius: 10px;
  padding: 24px 28px;
  box-shadow: 0 8px 30px rgba(15, 23, 42, 0.06);
}
h1, h2, h3 { color: #0b3c5d; }
h1 { margin-top: 0; }
code {
  background: #eef3f8;
  border-radius: 4px;
  padding: 0 4px;
  font-family: Consolas, "Courier New", monospace;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin: 10px 0 18px;
}
th, td {
  border: 1px solid #d9e2ec;
  padding: 8px 10px;
  text-align: left;
  vertical-align: top;
}
th { background: #edf2f7; }
ul { margin: 8px 0 14px; }
"""
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"zh-CN\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "  <title>JuiceChain 渗透测试报告</title>\n"
        f"  <style>{css}</style>\n"
        "</head>\n"
        "<body>\n"
        f"<main>\n{body}\n</main>\n"
        "</body>\n"
        "</html>\n"
    )


def _extract_scan_context(scan_data: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(scan_data, Mapping):
        return {}, {}

    if all(k in scan_data for k in ("alive", "info", "enum")):
        meta = scan_data.get("meta")
        return _as_dict(meta), dict(scan_data)

    meta = scan_data.get("meta")
    data = scan_data.get("data")
    if isinstance(meta, Mapping) and meta.get("command") == "scan" and isinstance(data, Mapping):
        if all(k in data for k in ("alive", "info", "enum")):
            return dict(meta), dict(data)

    return _as_dict(scan_data.get("meta")), dict(scan_data)


def _extract_vuln_context(vuln_data: Mapping[str, Any] | None) -> dict[str, Any]:
    if vuln_data is None:
        return {}
    if not isinstance(vuln_data, Mapping):
        return {}

    if isinstance(vuln_data.get("findings"), list):
        return dict(vuln_data)

    meta = vuln_data.get("meta")
    data = vuln_data.get("data")
    if isinstance(meta, Mapping) and meta.get("command") == "vuln" and isinstance(data, Mapping):
        if isinstance(data.get("findings"), list):
            return dict(data)

    return {}


def _severity_counts(findings: list[Any]) -> dict[str, int]:
    out = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        level = str(finding.get("severity") or "").strip().lower()
        if level in out:
            out[level] += 1
    return out


def _sort_findings(findings: list[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in findings:
        if isinstance(item, Mapping):
            normalized.append(dict(item))

    def _key(finding: Mapping[str, Any]) -> tuple[int, str]:
        sev = str(finding.get("severity") or "").strip().lower()
        return (_SEVERITY_ORDER.get(sev, 99), str(finding.get("type") or ""))

    return sorted(normalized, key=_key)


def _finding_path(request: Mapping[str, Any]) -> str:
    raw = str(request.get("url") or request.get("path") or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw)
    if parsed.path:
        if parsed.query:
            return f"{parsed.path}?{parsed.query}"
        return parsed.path
    return raw


def _build_recommendations(findings: list[Any]) -> list[str]:
    keys: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        ftype = str(finding.get("type") or "").upper()
        for marker in _RECOMMENDATION_MAP:
            if marker in ftype:
                keys.add(marker)

    ordered = sorted(keys)
    if not ordered:
        return [
            "持续维护依赖与框架补丁，建立周期性扫描与人工复核流程。",
            "为关键路径增加统一鉴权、输入校验、审计日志和异常告警。",
        ]
    return [_RECOMMENDATION_MAP[key] for key in ordered]


def _markdown_bullets(items: list[str], *, fallback: str, max_items: int = 40) -> list[str]:
    if not items:
        return [fallback]
    out = [f"- `{item}`" for item in items[:max_items]]
    if len(items) > max_items:
        out.append(f"- ... 其余 {len(items) - max_items} 项省略")
    return out


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _as_str_list(value: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(value, list):
        return out
    for item in value:
        if not isinstance(item, str):
            continue
        s = item.strip()
        if s:
            out.append(s)
    return out


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_json_like(value: Any) -> str:
    if value is None:
        return "[]"
    if isinstance(value, (list, dict)):
        return str(value)
    return _safe_str(value)


def _format_timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OverflowError, OSError, ValueError):
            pass
    return "unknown"


def _md_cell(value: str) -> str:
    cell = (value or "").replace("\n", " ").replace("\r", " ").strip()
    if not cell:
        return "-"
    return cell.replace("|", "\\|")


def _render_markdown_body(markdown: str) -> str:
    lines = markdown.splitlines()
    out: list[str] = []
    i = 0
    in_list = False

    def _close_list() -> None:
        nonlocal in_list
        if in_list:
            out.append("</ul>")
            in_list = False

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("|"):
            _close_list()
            table_lines: list[str] = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1
            out.append(_table_to_html(table_lines))
            continue

        if not stripped:
            _close_list()
            i += 1
            continue

        if stripped.startswith("# "):
            _close_list()
            out.append(f"<h1>{_inline_html(stripped[2:].strip())}</h1>")
            i += 1
            continue
        if stripped.startswith("## "):
            _close_list()
            out.append(f"<h2>{_inline_html(stripped[3:].strip())}</h2>")
            i += 1
            continue
        if stripped.startswith("### "):
            _close_list()
            out.append(f"<h3>{_inline_html(stripped[4:].strip())}</h3>")
            i += 1
            continue

        if stripped.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline_html(stripped[2:].strip())}</li>")
            i += 1
            continue

        _close_list()
        out.append(f"<p>{_inline_html(stripped)}</p>")
        i += 1

    _close_list()
    return "\n".join(out)


def _table_to_html(lines: list[str]) -> str:
    rows: list[list[str]] = []
    for line in lines:
        cells = [c.strip() for c in line.strip("|").split("|")]
        rows.append(cells)
    if len(rows) < 2:
        return ""

    header = rows[0]
    data_rows = rows[2:] if len(rows) >= 2 else []

    out = ["<table>", "<thead>", "<tr>"]
    out.extend(f"<th>{_inline_html(cell)}</th>" for cell in header)
    out.extend(["</tr>", "</thead>", "<tbody>"])
    for row in data_rows:
        out.append("<tr>")
        padded = row + [""] * (len(header) - len(row))
        for cell in padded[: len(header)]:
            out.append(f"<td>{_inline_html(cell)}</td>")
        out.append("</tr>")
    out.extend(["</tbody>", "</table>"])
    return "\n".join(out)


def _inline_html(text: str) -> str:
    escaped = escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped
