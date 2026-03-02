from __future__ import annotations

import json
import time
from typing import Any, cast


def normalize_errors(errors: list[Any] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for e in errors or []:
        s = str(e).strip()
        if s and s not in seen:
            out.append(s)
            seen.add(s)
    return out


def build_cli_payload(
    *,
    command: str,
    version: str,
    target: str | None,
    started_at: float,
    data: Any,
    errors: list[Any] | None = None,
    ok: bool | None = None,
) -> dict[str, Any]:
    normalized_errors = normalize_errors(errors)
    resolved_ok = bool(ok) if ok is not None else (len(normalized_errors) == 0)
    return {
        "meta": {
            "tool": "juicechain",
            "version": version,
            "command": command,
            "schema": "juicechain.cli.result/v1",
            "timestamp": int(time.time()),
            "duration_ms": int(round((time.perf_counter() - started_at) * 1000)),
        },
        "ok": resolved_ok,
        "target": target,
        "data": data,
        "errors": normalized_errors,
    }


def render_payload(payload: dict[str, Any], *, fmt: str = "json", pretty: bool = False) -> str:
    mode = (fmt or "json").strip().lower()
    if mode == "table":
        return _render_table(payload)
    return json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None)


def serialize_payload(payload: dict[str, Any], *, pretty: bool = False) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2 if pretty else None)


def _render_table(payload: dict[str, Any]) -> str:
    rows: list[tuple[str, str]] = []

    meta = _as_dict(payload.get("meta"))
    rows.append(("command", _safe_str(meta.get("command"))))
    rows.append(("version", _safe_str(meta.get("version"))))
    rows.append(("ok", _safe_str(payload.get("ok"))))
    rows.append(("target", _safe_str(payload.get("target"))))
    rows.append(("duration_ms", _safe_str(meta.get("duration_ms"))))

    command = str(meta.get("command") or "")
    rows.extend(_command_summary_rows(command, payload.get("data")))

    errors = payload.get("errors")
    if isinstance(errors, list):
        rows.append(("errors_count", str(len(errors))))
        for i, err in enumerate(errors[:3], start=1):
            rows.append((f"error_{i}", _safe_str(err, max_len=160)))

    return _tabulate_rows(rows)


def _command_summary_rows(command: str, data: Any) -> list[tuple[str, str]]:
    if not isinstance(data, dict):
        return []

    if command == "alive":
        return [
            ("alive", _safe_str(data.get("alive"))),
            ("status_code", _safe_str(data.get("status_code"))),
            ("response_time_ms", _safe_str(data.get("response_time_ms"))),
        ]

    if command == "info":
        home = _as_dict(data.get("homepage"))
        sec = _as_dict(data.get("security_headers"))
        missing = _as_list(sec.get("missing"))
        return [
            ("homepage_status", _safe_str(home.get("status_code"))),
            ("homepage_title", _safe_str(home.get("title"), max_len=80)),
            ("missing_security_headers", str(len(missing))),
        ]

    if command == "enum":
        crawler = _as_dict(data.get("crawler"))
        pages = _as_list(crawler.get("pages_fetched"))
        urls = _as_list(crawler.get("urls_discovered"))
        cd = _as_dict(data.get("content_discovery"))
        server_eps = _as_list(cd.get("findings_server_endpoints"))
        return [
            ("pages_fetched", str(len(pages))),
            ("urls_discovered", str(len(urls))),
            ("server_endpoints", str(len(server_eps))),
        ]

    if command == "scan":
        alive = _as_dict(data.get("alive"))
        enum = _as_dict(data.get("enum"))
        crawler = _as_dict(enum.get("crawler"))
        pages = _as_list(crawler.get("pages_fetched"))
        return [
            ("alive", _safe_str(alive.get("alive"))),
            ("alive_status", _safe_str(alive.get("status_code"))),
            ("pages_fetched", str(len(pages))),
        ]

    if command == "vuln":
        findings = _as_list(data.get("findings"))
        points = _as_dict(data.get("input_points"))
        return [
            ("input_points", _safe_str(points.get("total"))),
            ("findings", str(len(findings))),
        ]

    if command == "report":
        return [
            ("output_file", _safe_str(data.get("output_file"))),
            ("line_count", _safe_str(data.get("line_count"))),
        ]

    out: list[tuple[str, str]] = []
    for k, v in data.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out.append((str(k), _safe_str(v)))
    return out[:8]


def _safe_str(value: Any, *, max_len: int = 120) -> str:
    if isinstance(value, (dict, list)):
        s = json.dumps(value, ensure_ascii=False)
    else:
        s = "null" if value is None else str(value)
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _tabulate_rows(rows: list[tuple[str, str]]) -> str:
    try:
        from tabulate import tabulate

        return cast(str, tabulate(rows, headers=["Field", "Value"], tablefmt="github"))
    except Exception:
        key_w = max(len("Field"), *(len(k) for k, _ in rows))
        val_w = max(len("Value"), *(len(v) for _, v in rows))
        border = f"+-{'-' * key_w}-+-{'-' * val_w}-+"
        lines = [
            border,
            f"| {'Field'.ljust(key_w)} | {'Value'.ljust(val_w)} |",
            border,
        ]
        for k, v in rows:
            lines.append(f"| {k.ljust(key_w)} | {v.ljust(val_w)} |")
        lines.append(border)
        return "\n".join(lines)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []
