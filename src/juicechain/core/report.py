from __future__ import annotations

import json
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

_SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}

_RECOMMENDATION_MAP = {
    "XSS": "对所有用户输入执行上下文相关输出编码（HTML/属性/JS），并部署 CSP 限制脚本来源与执行。",
    "SQLI": "数据库访问统一使用参数化查询或 ORM 绑定变量，禁止拼接 SQL 字符串。",
    "AUTH": "认证与登录链路加入失败次数限制、MFA、会话绑定与异常登录告警。",
    "REDIRECT": "重定向目标使用白名单与签名校验，禁止直接信任用户可控跳转参数。",
    "TRAVERSAL": "文件访问路径做规范化与目录边界校验，仅允许访问白名单目录中的资源。",
}


def build_scan_report(scan_data: Mapping[str, Any], vuln_data: Mapping[str, Any] | None = None) -> str:
    """Build a Chinese-first Markdown report from scan and optional vuln payloads."""
    scan_meta, scan_doc = _extract_scan_context(scan_data)
    vuln_doc = _extract_vuln_context(vuln_data)

    findings = _as_list(vuln_doc.get("findings"))
    sorted_findings = _sort_findings(findings)
    severity = _severity_counts(findings)
    total_findings = sum(severity.values())

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
    route_paths = _as_str_list(spa.get("route_paths_from_assets"))
    hash_routes = _as_str_list(crawler.get("hash_routes"))
    api_candidates = _as_str_list(spa.get("api_candidates_from_assets"))
    server_endpoints = _as_list(content_discovery.get("findings_server_endpoints"))
    spa_routes = _as_list(content_discovery.get("findings_spa_routes"))
    fallback_noise = _as_list(content_discovery.get("findings_fallback_noise"))
    has_spa_signals = bool(routes or route_paths or hash_routes)

    lines: list[str] = []
    lines.append("# JuiceChain 安全测试报告")
    lines.append("")

    lines.append("## 1. 执行概览")
    lines.append(f"- 目标：`{target}`")
    lines.append(f"- 扫描时间：{scan_time}")
    lines.append(f"- 工具版本：{tool_version}")
    lines.append(f"- 连通性：{_alive_summary(alive)}")
    if vuln_data is None:
        lines.append("- 漏洞数据：未提供（仅展示 scan 阶段结果）")
    else:
        lines.append("- 漏洞数据：已提供（包含主动验证结果）")
    lines.append(
        "- 漏洞统计："
        f"严重 {severity['critical']} | 高危 {severity['high']} | 中危 {severity['medium']} | "
        f"低危 {severity['low']} | 信息 {severity['info']} | 总计 {total_findings}"
    )
    lines.append("")

    lines.append("## 2. 目标与攻击面")
    lines.append("### 2.1 目标指纹")
    lines.append(f"- 首页：{_homepage_summary(homepage)}")
    lines.append(
        "- 服务端："
        f"{_safe_str(fingerprint.get('server')) or 'unknown'}；"
        f"框架：{_safe_str(fingerprint.get('x_powered_by')) or 'unknown'}；"
        f"线索：{_safe_json_like(fingerprint.get('hints'))}"
    )
    lines.append(
        "- 安全响应头："
        f"缺失={_safe_json_like(security_headers.get('missing'))}；"
        f"已存在={_safe_json_like(_dict_keys(security_headers.get('present')))}；"
        f"过时={_safe_json_like(_dict_keys(security_headers.get('deprecated_present')))}"
    )
    lines.append("")

    lines.append("### 2.2 攻击面统计")
    lines.append("| 指标 | 数量 |")
    lines.append("| --- | --- |")
    lines.append(f"| 页面链接 | {len(pages)} |")
    lines.append(f"| SPA 路由 | {len(routes)} |")
    lines.append(f"| SPA 路径片段 | {len(route_paths)} |")
    lines.append(f"| Hash 路由 | {len(hash_routes)} |")
    lines.append(f"| API 候选端点 | {len(api_candidates)} |")
    lines.append(f"| 服务端端点 | {len(server_endpoints)} |")
    lines.append(f"| SPA 路由映射 | {len(spa_routes)} |")
    lines.append(f"| Fallback 噪声 | {len(fallback_noise)} |")
    lines.append("")

    lines.append("### 2.3 SPA 路由（最多 40 条）")
    lines.extend(_markdown_bullets(routes, fallback="- 未发现 SPA 路由。"))
    lines.append("")
    lines.append("### 2.4 API 候选端点（最多 40 条）")
    lines.extend(_markdown_bullets(api_candidates, fallback="- 未发现 API 候选端点。"))
    lines.append("")

    if vuln_data is not None:
        lines.append("## 3. 漏洞概览")
        if sorted_findings:
            lines.append("### 3.1 按严重级别统计")
            lines.append("| 严重级别 | 数量 |")
            lines.append("| --- | --- |")
            for key in ("critical", "high", "medium", "low", "info"):
                lines.append(f"| {_SEVERITY_LABEL[key]} | {severity[key]} |")
            lines.append("")

            lines.append("### 3.2 按漏洞类型统计")
            lines.append("| 漏洞类型 | 数量 |")
            lines.append("| --- | --- |")
            for vuln_type, count in _type_counts(sorted_findings):
                lines.append(f"| {vuln_type} | {count} |")
        else:
            lines.append("- 未发现漏洞。")
        lines.append("")

        lines.append("## 4. 漏洞详情")
        if sorted_findings:
            for idx, finding in enumerate(sorted_findings, start=1):
                request = _as_dict(finding.get("request"))
                response = _as_dict(finding.get("response"))
                sev_key = _safe_str(finding.get("severity")).lower()
                sev_text = _SEVERITY_LABEL.get(sev_key, _safe_str(finding.get("severity")) or "未知")
                vuln_type = _safe_str(finding.get("type")) or "UNKNOWN"

                lines.append(f"### 4.{idx} [{sev_text}] {vuln_type}")
                lines.append(f"- 路径：`{_finding_path(request) or '-'}`")
                lines.append(f"- 参数：`{_safe_str(request.get('param')) or '-'}`")
                lines.append(f"- 注入位置：`{_safe_str(request.get('location')) or '-'}`")
                lines.append(f"- Payload：`{_safe_str(request.get('payload')) or '-'}`")
                lines.append(f"- 证据：{_safe_str(finding.get('evidence')) or '-'}")
                lines.append(f"- 响应：{_response_summary(response)}")
                lines.append("")
        else:
            lines.append("- 无可展示的漏洞详情。")
            lines.append("")

    lines.append("## 5. 修复建议")
    if has_spa_signals and not sorted_findings:
        lines.append("- 检测到 SPA 特征但未发现漏洞，建议启用 `--dom-xss` 进行浏览器侧 DOM XSS 验证。")
    for rec in _build_recommendations(sorted_findings):
        lines.append(f"- {rec}")

    return "\n".join(lines)


def markdown_to_html(markdown: str) -> str:
    """Render report Markdown into a standalone HTML document."""
    body = _render_markdown_body(markdown)
    css = """
body {
  margin: 0;
  background: linear-gradient(180deg, #f8fafc 0%, #eef4ff 100%);
  color: #1f2937;
  font-family: "Noto Sans SC", "PingFang SC", "Microsoft YaHei", "Segoe UI", sans-serif;
  line-height: 1.68;
}
main {
  max-width: 1040px;
  margin: 26px auto;
  background: #ffffff;
  border: 1px solid #e5e7eb;
  border-radius: 12px;
  padding: 30px 34px;
  box-shadow: 0 12px 34px rgba(15, 23, 42, 0.08);
}
h1, h2, h3 {
  color: #0f172a;
}
h1 {
  margin-top: 0;
  border-bottom: 2px solid #e2e8f0;
  padding-bottom: 10px;
}
h2 {
  margin-top: 24px;
  padding-left: 10px;
  border-left: 4px solid #2563eb;
}
h3 {
  margin-top: 16px;
}
p {
  margin: 8px 0;
}
code {
  background: #eff6ff;
  border-radius: 4px;
  padding: 1px 5px;
  font-family: Consolas, "Courier New", monospace;
  word-break: break-all;
}
table {
  width: 100%;
  border-collapse: collapse;
  margin: 10px 0 18px;
  table-layout: fixed;
}
th, td {
  border: 1px solid #e5e7eb;
  padding: 8px 10px;
  text-align: left;
  vertical-align: top;
  word-break: break-word;
}
th {
  background: #f1f5f9;
  font-weight: 600;
}
tbody tr:nth-child(even) {
  background: #fafafa;
}
ul {
  margin: 8px 0 14px;
  padding-left: 22px;
}
"""
    return (
        "<!DOCTYPE html>\n"
        '<html lang="zh-CN">\n'
        "<head>\n"
        '  <meta charset="utf-8">\n'
        '  <meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "  <title>JuiceChain 安全测试报告</title>\n"
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

    if all(key in scan_data for key in ("alive", "info", "enum")):
        return _as_dict(scan_data.get("meta")), dict(scan_data)

    meta = scan_data.get("meta")
    data = scan_data.get("data")
    if isinstance(meta, Mapping) and meta.get("command") == "scan" and isinstance(data, Mapping):
        if all(key in data for key in ("alive", "info", "enum")):
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
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
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
        return f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    return raw


def _type_counts(findings: list[dict[str, Any]]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for finding in findings:
        vuln_type = _safe_str(finding.get("type")) or "UNKNOWN"
        counts[vuln_type] = counts.get(vuln_type, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _build_recommendations(findings: list[Any]) -> list[str]:
    markers: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        finding_type = str(finding.get("type") or "").upper()
        if "XSS" in finding_type:
            markers.add("XSS")
        if "SQLI" in finding_type:
            markers.add("SQLI")
        if "AUTH" in finding_type:
            markers.add("AUTH")
        if "REDIRECT" in finding_type:
            markers.add("REDIRECT")
        if "TRAVERSAL" in finding_type:
            markers.add("TRAVERSAL")

    if not markers:
        return [
            "建立持续漏洞扫描与人工复核流程，确保高风险变更上线前完成安全验收。",
            "对认证、输入校验、日志审计、依赖升级设置统一安全基线并定期检查。",
        ]

    ordered = sorted(markers)
    return [_RECOMMENDATION_MAP[key] for key in ordered if key in _RECOMMENDATION_MAP]


def _homepage_summary(homepage: Mapping[str, Any]) -> str:
    if not homepage:
        return "unknown"
    url = _safe_str(homepage.get("url")) or "unknown"
    status_code = _safe_str(homepage.get("status_code")) or "unknown"
    return f"{url}（状态码={status_code}）"


def _alive_summary(alive: Mapping[str, Any]) -> str:
    alive_raw = alive.get("alive")
    if alive_raw is True:
        state = "存活"
    elif alive_raw is False:
        state = "不可达"
    else:
        state = "未知"
    status = _safe_str(alive.get("status_code")) or "unknown"
    rtt = _safe_str(alive.get("response_time_ms")) or "unknown"
    return f"{state}（状态码={status}，响应时间={rtt} ms）"


def _response_summary(response: Mapping[str, Any]) -> str:
    status_code = _safe_str(response.get("status_code")) or "unknown"
    content_type = _safe_str(response.get("content_type")) or "unknown"
    time_ms = _safe_str(response.get("time_ms")) or "unknown"
    return f"状态码={status_code}，类型={content_type}，耗时={time_ms} ms"


def _dict_keys(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [str(key) for key in value.keys()]
    return []


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
        stripped = item.strip()
        if stripped:
            out.append(stripped)
    return out


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_json_like(value: Any) -> str:
    if value is None:
        return "[]"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return _safe_str(value)


def _format_timestamp(value: Any) -> str:
    if isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OverflowError, OSError, ValueError):
            pass
    return "unknown"


def _inline_html(text: str) -> str:
    escaped = escape(text)
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return escaped


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
        rows.append([cell.strip() for cell in line.strip("|").split("|")])
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
