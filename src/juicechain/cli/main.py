from __future__ import annotations

import argparse
import json
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable

from juicechain.core.alive import check_http_alive
from juicechain.core.enumeration import enumerate_attack_surface
from juicechain.core.info_gather import gather_info
from juicechain.core.vulnerability import scan_vulnerabilities, vuln_dry_run_report
from juicechain.utils.logging import DEFAULT_LOG_FILE, configure_logging, get_logger
from juicechain.utils.output import build_cli_payload, normalize_errors, render_payload, serialize_payload


class CliUsageError(Exception):
    pass


def _get_version() -> str:
    try:
        return version("juicechain")
    except PackageNotFoundError:
        return "0.0.0"


def _load_json_input(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise CliUsageError(f"input file not found: {path}") from e
    except UnicodeDecodeError as e:
        raise CliUsageError(f"input file is not valid UTF-8: {path} ({e})") from e
    except OSError as e:
        raise CliUsageError(f"failed to read input file: {path} ({e})") from e

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise CliUsageError(
            f"invalid JSON in {path} at line {e.lineno}, column {e.colno}: {e.msg}"
        ) from e


def _extract_scan_document(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise CliUsageError("scan input must be a JSON object")

    if all(k in doc for k in ("alive", "info", "enum")):
        return doc

    meta = doc.get("meta")
    data = doc.get("data")
    if isinstance(meta, dict) and meta.get("command") == "scan" and isinstance(data, dict):
        if all(k in data for k in ("alive", "info", "enum")):
            return data

    raise CliUsageError("input JSON is not a valid scan result")


def _extract_errors_from_obj(obj: Any) -> list[str]:
    if not isinstance(obj, dict):
        return []

    out: list[str] = []
    e = obj.get("error")
    if isinstance(e, str) and e.strip():
        out.append(e.strip())

    errs = obj.get("errors")
    if isinstance(errs, list):
        out.extend(normalize_errors(errs))
    return normalize_errors(out)


def _extract_scan_errors(scan_data: Any) -> list[str]:
    if not isinstance(scan_data, dict):
        return ["scan result is not a JSON object"]
    out: list[str] = []
    out.extend(_extract_errors_from_obj(scan_data.get("alive")))
    out.extend(_extract_errors_from_obj(scan_data.get("info")))
    out.extend(_extract_errors_from_obj(scan_data.get("enum")))
    return normalize_errors(out)


def _resolve_ok(data: Any, errors: list[str]) -> bool:
    if isinstance(data, dict) and isinstance(data.get("ok"), bool):
        return bool(data["ok"]) and len(errors) == 0
    return len(errors) == 0


def _resolve_ok_for_scan(data: Any, errors: list[str]) -> bool:
    if not isinstance(data, dict):
        return False
    alive = data.get("alive") if isinstance(data.get("alive"), dict) else {}
    return bool(alive.get("alive")) and len(errors) == 0


def _build_report_markdown(data: dict[str, Any]) -> str:
    md_lines: list[str] = []
    meta = data.get("meta", {})
    md_lines.append("# JuiceChain Report")
    md_lines.append("")
    md_lines.append(f"- Version: {meta.get('version')}")
    md_lines.append(f"- Timestamp: {meta.get('timestamp')}")
    md_lines.append(f"- Duration(ms): {meta.get('duration_ms')}")
    md_lines.append(f"- Target: {data.get('target')}")
    md_lines.append("")

    alive_data = data.get("alive", {})
    md_lines.append("## Liveness")
    md_lines.append("")
    md_lines.append(f"- Alive: {alive_data.get('alive')}")
    md_lines.append(f"- Status: {alive_data.get('status_code')}")
    md_lines.append(f"- RTT(ms): {alive_data.get('response_time_ms')}")
    if alive_data.get("error"):
        md_lines.append(f"- Error: {alive_data.get('error')}")
    md_lines.append("")

    info_data = data.get("info", {})
    md_lines.append("## Passive Info")
    md_lines.append("")
    hp = info_data.get("homepage", {}) or {}
    md_lines.append(f"- Homepage URL: {hp.get('url')}")
    md_lines.append(f"- Status: {hp.get('status_code')}")
    md_lines.append(f"- Title: {hp.get('title')}")
    fp = info_data.get("fingerprint", {}) or {}
    md_lines.append(
        f"- Fingerprint: server={fp.get('server')} x_powered_by={fp.get('x_powered_by')} hints={fp.get('hints')}"
    )
    sh = info_data.get("security_headers", {}) or {}
    md_lines.append(f"- Missing security headers: {sh.get('missing')}")
    dep = sh.get("deprecated_present") or {}
    if dep:
        md_lines.append(f"- Deprecated security headers present: {dep}")
    spa_hints = info_data.get("spa_hints") or {}
    if spa_hints:
        md_lines.append(f"- SPA hints: {spa_hints}")
    md_lines.append("")

    enum_data = data.get("enum", {})
    md_lines.append("## Attack Surface Enumeration")
    md_lines.append("")
    crawler = enum_data.get("crawler", {}) or {}
    pages = crawler.get("pages_fetched", []) or []
    md_lines.append(f"- Pages fetched: {len(pages)}")
    md_lines.append(f"- Hash routes (from html/headers): {crawler.get('hash_routes')}")
    spa = crawler.get("spa") or {}
    md_lines.append(f"- SPA routes (from assets): {spa.get('routes_from_assets')}")
    md_lines.append(f"- API candidates (from assets): {spa.get('api_candidates_from_assets')}")
    md_lines.append("")

    cd = enum_data.get("content_discovery", {}) or {}
    conf = cd.get("findings_server_endpoints", []) or []
    spa_routes = cd.get("findings_spa_routes", []) or []
    noise = cd.get("findings_fallback_noise", []) or []
    md_lines.append(f"- Server endpoints: {len(conf)}")
    md_lines.append(f"- SPA routes mapped: {len(spa_routes)}")
    md_lines.append(f"- Fallback noise: {len(noise)}")
    md_lines.append("")

    return "\n".join(md_lines)


def _configure_runtime_logging(args: argparse.Namespace) -> None:
    enable_file = not bool(getattr(args, "no_log_file", False))
    file_path = configure_logging(
        level=str(getattr(args, "log_level", "INFO")),
        log_file=str(getattr(args, "log_file", DEFAULT_LOG_FILE)),
        enable_file=enable_file,
    )
    logger = get_logger(__name__)
    if file_path:
        logger.debug("log file enabled: %s", file_path)
    else:
        logger.debug("log file disabled")


def _emit_payload(args: argparse.Namespace, payload: dict[str, Any]) -> None:
    path = getattr(args, "output", None)
    if path:
        text = serialize_payload(payload, pretty=bool(getattr(args, "pretty", False)))
        Path(path).write_text(text, encoding="utf-8")
        return

    text = render_payload(
        payload,
        fmt=str(getattr(args, "format", "json")),
        pretty=bool(getattr(args, "pretty", False)),
    )
    print(text)


def _run_command(
    args: argparse.Namespace,
    *,
    command: str,
    target: str | None,
    runner: Callable[[], Any],
    error_extractor: Callable[[Any], list[str]] = _extract_errors_from_obj,
    ok_resolver: Callable[[Any, list[str]], bool] = _resolve_ok,
) -> int:
    _configure_runtime_logging(args)
    logger = get_logger(f"{__name__}.{command}")
    started = time.perf_counter()
    cli_version = _get_version()

    try:
        logger.info("command start: %s target=%s", command, target)
        data = runner()
        errors = normalize_errors(error_extractor(data))
        ok = ok_resolver(data, errors)
        payload = build_cli_payload(
            command=command,
            version=cli_version,
            target=target,
            started_at=started,
            data=data,
            errors=errors,
            ok=ok,
        )
        logger.info("command done: %s ok=%s errors=%d", command, ok, len(errors))
        _emit_payload(args, payload)
        return 0 if ok else 1
    except CliUsageError as e:
        logger.error("usage error: %s", e)
        payload = build_cli_payload(
            command=command,
            version=cli_version,
            target=target,
            started_at=started,
            data=None,
            errors=[str(e)],
            ok=False,
        )
        print(render_payload(payload, fmt="json", pretty=True))
        return 2
    except Exception as e:
        logger.exception("command failed: %s", command)
        payload = build_cli_payload(
            command=command,
            version=cli_version,
            target=target,
            started_at=started,
            data=None,
            errors=[f"{type(e).__name__}: {e}"],
            ok=False,
        )
        print(render_payload(payload, fmt="json", pretty=True))
        return 1


def _add_runtime_options(parser: argparse.ArgumentParser, *, allow_output_file: bool) -> None:
    parser.add_argument(
        "--format",
        choices=("json", "table"),
        default="json",
        help="Result display format (default: json)",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="INFO",
        help="Console log level (default: INFO)",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=str(DEFAULT_LOG_FILE),
        help=f"Log file path (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--no-log-file",
        action="store_true",
        help="Disable file logging and only log to console",
    )
    if allow_output_file:
        parser.add_argument(
            "-o",
            "--output",
            type=str,
            default=None,
            help="Write structured result JSON to file",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="juicechain",
        description="JuiceChain: lightweight recon & enumeration toolchain (authorized targets only)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_get_version()}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run pipeline: alive -> info -> enum")
    scan.add_argument("-t", "--target", required=True, help="Target URL or host[:port]")
    scan.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds (default: 3.0)")
    scan.add_argument("--max-pages", type=int, default=30, help="Max pages to fetch in crawler (default: 30)")
    scan.add_argument(
        "--max-bytes",
        type=int,
        default=300_000,
        help="Max bytes to read per response (default: 300000)",
    )
    scan.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: false)")
    scan.add_argument("--insecure", action="store_true", help="Disable TLS cert verification (default: false)")
    scan.add_argument("--retries", type=int, default=0, help="Retry count on network errors (default: 0)")
    scan.add_argument(
        "--rate-limit-ms",
        type=int,
        default=0,
        help="Min interval between requests in ms (default: 0)",
    )
    scan.add_argument("--wordlist", type=str, default=None, help="Path to custom wordlist file (optional)")
    scan.add_argument("--no-spa-assets", action="store_true", help="Disable SPA asset fetching (default: false)")
    scan.add_argument("--max-spa-assets", type=int, default=6, help="Max JS assets to fetch (default: 6)")
    scan.add_argument(
        "--spa-asset-bytes",
        type=int,
        default=450_000,
        help="Max bytes per JS asset fetch (default: 450000)",
    )
    _add_runtime_options(scan, allow_output_file=True)

    def _scan_cmd(args: argparse.Namespace) -> int:
        verify_tls = not args.insecure
        allow_redirects = bool(args.follow_redirects)

        def _runner() -> dict[str, Any]:
            return {
                "target": args.target,
                "alive": check_http_alive(
                    args.target,
                    timeout=args.timeout,
                    verify_tls=verify_tls,
                    allow_redirects=allow_redirects,
                    retries=args.retries,
                ),
                "info": gather_info(
                    args.target,
                    timeout=args.timeout,
                    verify_tls=verify_tls,
                    allow_redirects=allow_redirects,
                    max_bytes=args.max_bytes,
                    retries=args.retries,
                ),
                "enum": enumerate_attack_surface(
                    args.target,
                    timeout=args.timeout,
                    max_pages=args.max_pages,
                    max_bytes=args.max_bytes,
                    wordlist_file=args.wordlist,
                    allow_redirects=allow_redirects,
                    verify_tls=verify_tls,
                    retries=args.retries,
                    min_interval_ms=args.rate_limit_ms,
                    fetch_spa_assets=not args.no_spa_assets,
                    max_spa_assets=args.max_spa_assets,
                    spa_asset_max_bytes=args.spa_asset_bytes,
                ),
            }

        return _run_command(
            args,
            command="scan",
            target=args.target,
            runner=_runner,
            error_extractor=_extract_scan_errors,
            ok_resolver=_resolve_ok_for_scan,
        )

    scan.set_defaults(func=_scan_cmd)

    alive = subparsers.add_parser("alive", help="Check target liveness via HTTP")
    alive.add_argument("-t", "--target", required=True, help="Target URL or host[:port]")
    alive.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds (default: 3.0)")
    alive.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: false)")
    alive.add_argument("--insecure", action="store_true", help="Disable TLS cert verification (default: false)")
    alive.add_argument("--retries", type=int, default=0, help="Retry count on network errors (default: 0)")
    _add_runtime_options(alive, allow_output_file=False)

    def _alive_cmd(args: argparse.Namespace) -> int:
        return _run_command(
            args,
            command="alive",
            target=args.target,
            runner=lambda: check_http_alive(
                args.target,
                timeout=args.timeout,
                verify_tls=not args.insecure,
                allow_redirects=bool(args.follow_redirects),
                retries=args.retries,
            ),
        )

    alive.set_defaults(func=_alive_cmd)

    info = subparsers.add_parser("info", help="Passive info gathering (headers/title/robots + basic audit)")
    info.add_argument("-t", "--target", required=True, help="Target URL or host[:port]")
    info.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds (default: 3.0)")
    info.add_argument(
        "--max-bytes",
        type=int,
        default=256_000,
        help="Max bytes to read per response (default: 256000)",
    )
    info.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: false)")
    info.add_argument("--insecure", action="store_true", help="Disable TLS cert verification (default: false)")
    info.add_argument("--retries", type=int, default=0, help="Retry count on network errors (default: 0)")
    _add_runtime_options(info, allow_output_file=False)

    def _info_cmd(args: argparse.Namespace) -> int:
        return _run_command(
            args,
            command="info",
            target=args.target,
            runner=lambda: gather_info(
                args.target,
                timeout=args.timeout,
                verify_tls=not args.insecure,
                allow_redirects=bool(args.follow_redirects),
                max_bytes=args.max_bytes,
                retries=args.retries,
            ),
        )

    info.set_defaults(func=_info_cmd)

    enum_cmd = subparsers.add_parser(
        "enum",
        help="Attack surface enumeration (crawler + content discovery)",
    )
    enum_cmd.add_argument("-t", "--target", required=True, help="Target URL or host[:port]")
    enum_cmd.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds (default: 3.0)")
    enum_cmd.add_argument("--max-pages", type=int, default=30, help="Max pages to fetch in crawler (default: 30)")
    enum_cmd.add_argument(
        "--max-bytes",
        type=int,
        default=300_000,
        help="Max bytes to read per response (default: 300000)",
    )
    enum_cmd.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: false)")
    enum_cmd.add_argument("--insecure", action="store_true", help="Disable TLS cert verification (default: false)")
    enum_cmd.add_argument("--retries", type=int, default=0, help="Retry count on network errors (default: 0)")
    enum_cmd.add_argument(
        "--rate-limit-ms",
        type=int,
        default=0,
        help="Min interval between requests in ms (default: 0)",
    )
    enum_cmd.add_argument("--wordlist", type=str, default=None, help="Path to custom wordlist file (optional)")
    enum_cmd.add_argument("--no-spa-assets", action="store_true", help="Disable SPA asset fetching (default: false)")
    enum_cmd.add_argument("--max-spa-assets", type=int, default=6, help="Max JS assets to fetch (default: 6)")
    enum_cmd.add_argument(
        "--spa-asset-bytes",
        type=int,
        default=450_000,
        help="Max bytes per JS asset fetch (default: 450000)",
    )
    _add_runtime_options(enum_cmd, allow_output_file=False)

    def _enum_cmd(args: argparse.Namespace) -> int:
        return _run_command(
            args,
            command="enum",
            target=args.target,
            runner=lambda: enumerate_attack_surface(
                args.target,
                timeout=args.timeout,
                max_pages=args.max_pages,
                max_bytes=args.max_bytes,
                wordlist_file=args.wordlist,
                allow_redirects=bool(args.follow_redirects),
                verify_tls=not args.insecure,
                retries=args.retries,
                min_interval_ms=args.rate_limit_ms,
                fetch_spa_assets=not args.no_spa_assets,
                max_spa_assets=args.max_spa_assets,
                spa_asset_max_bytes=args.spa_asset_bytes,
            ),
        )

    enum_cmd.set_defaults(func=_enum_cmd)

    vuln = subparsers.add_parser("vuln", help="Vulnerability module (week5: skeleton/dry-run)")
    vuln.add_argument("-i", "--input", required=True, help="Input JSON file (from juicechain scan)")
    vuln.add_argument("--dry-run", action="store_true", help="Only derive input points and output stats (no requests)")
    vuln.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout seconds (default: 3.0)")
    vuln.add_argument(
        "--max-bytes",
        type=int,
        default=200_000,
        help="Max response bytes to read (default: 200000)",
    )
    vuln.add_argument("--retries", type=int, default=0, help="Retry times (default: 0)")
    vuln.add_argument(
        "--rate-limit-ms",
        type=int,
        default=0,
        help="Min interval between requests in ms (default: 0)",
    )
    vuln.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    vuln.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    vuln.add_argument("--dom-xss", action="store_true", help="Enable DOM-XSS verification via Playwright")
    vuln.add_argument("--headed", action="store_true", help="Run browser in headed mode (for debugging)")
    _add_runtime_options(vuln, allow_output_file=True)

    def _vuln_cmd(args: argparse.Namespace) -> int:
        def _runner() -> dict[str, Any]:
            raw = _load_json_input(Path(args.input))
            scan_doc = _extract_scan_document(raw)
            if args.dry_run:
                return vuln_dry_run_report(scan_doc, version=_get_version())
            return scan_vulnerabilities(
                scan_doc,
                version=_get_version(),
                timeout=float(args.timeout),
                verify_tls=not bool(args.insecure),
                allow_redirects=bool(args.follow_redirects),
                retries=int(args.retries),
                min_interval_ms=int(args.rate_limit_ms),
                max_bytes=int(args.max_bytes),
                enable_dom_xss=bool(args.dom_xss),
                dom_xss_headless=not bool(args.headed),
            )

        return _run_command(
            args,
            command="vuln",
            target=args.input,
            runner=_runner,
        )

    vuln.set_defaults(func=_vuln_cmd)

    report = subparsers.add_parser("report", help="Generate a Markdown report from scan JSON")
    report.add_argument("-i", "--input", required=True, help="Input JSON file (from juicechain scan)")
    report.add_argument(
        "-o",
        "--output",
        dest="markdown_output",
        default=None,
        help="Output markdown file (default: stdout)",
    )
    _add_runtime_options(report, allow_output_file=False)

    def _report_cmd(args: argparse.Namespace) -> int:
        def _runner() -> dict[str, Any]:
            raw = _load_json_input(Path(args.input))
            scan_doc = _extract_scan_document(raw)
            out_md = _build_report_markdown(scan_doc)
            if args.markdown_output:
                Path(args.markdown_output).write_text(out_md, encoding="utf-8")
            return {
                "input_file": args.input,
                "output_file": args.markdown_output,
                "line_count": len(out_md.splitlines()),
                "markdown": None if args.markdown_output else out_md,
            }

        return _run_command(
            args,
            command="report",
            target=args.input,
            runner=_runner,
        )

    report.set_defaults(func=_report_cmd)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
