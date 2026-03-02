from __future__ import annotations

import argparse
import json
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable

from juicechain.core.report import build_scan_report, markdown_to_html
from juicechain.core.config import ScanConfig, default_config_template
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


def _extract_vuln_document(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict):
        raise CliUsageError("vuln input must be a JSON object")

    if isinstance(doc.get("findings"), list):
        return doc

    meta = doc.get("meta")
    data = doc.get("data")
    if isinstance(meta, dict) and meta.get("command") == "vuln" and isinstance(data, dict):
        if isinstance(data.get("findings"), list):
            return data

    raise CliUsageError("input JSON is not a valid vuln result")


def _load_scan_config(args: argparse.Namespace) -> ScanConfig:
    config_path = getattr(args, "config", None)
    try:
        return ScanConfig.from_cli_args(args)
    except FileNotFoundError as e:
        raise CliUsageError(f"config file not found: {config_path}") from e
    except OSError as e:
        raise CliUsageError(f"failed to read config file: {config_path} ({e})") from e
    except (ValueError, RuntimeError) as e:
        raise CliUsageError(f"invalid config file: {config_path} ({e})") from e


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
        # File output is always pretty for readability and manual review.
        text = serialize_payload(payload, pretty=True)
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


def _add_runtime_options(
    parser: argparse.ArgumentParser,
    *,
    allow_output_file: bool,
    include_format: bool = True,
    include_pretty: bool = True,
) -> None:
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default=None,
        help="Path to TOML config file",
    )
    if include_format:
        parser.add_argument(
            "--format",
            choices=("json", "table"),
            default="json",
            help="Result display format (default: json)",
        )
    if include_pretty:
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
    scan.add_argument("--timeout", type=float, default=None, help="HTTP timeout in seconds")
    scan.add_argument("--max-pages", type=int, default=None, help="Max pages to fetch in crawler")
    scan.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="Max bytes to read per response",
    )
    scan.add_argument("--follow-redirects", action="store_true", default=None, help="Follow redirects")
    scan.add_argument("--insecure", action="store_true", default=None, help="Disable TLS cert verification")
    scan.add_argument("--retries", type=int, default=None, help="Retry count on network errors")
    scan.add_argument(
        "--rate-limit-ms",
        type=int,
        default=None,
        help="Min interval between requests in ms",
    )
    scan.add_argument("--wordlist", type=str, default=None, help="Path to custom wordlist file (optional)")
    scan.add_argument(
        "--wordlist-category",
        choices=("common", "api", "backup", "all"),
        default="common",
        help="Built-in wordlist category when --wordlist is not provided (default: common)",
    )
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
        def _runner() -> dict[str, Any]:
            cfg = _load_scan_config(args)
            return {
                "target": args.target,
                "alive": check_http_alive(
                    args.target,
                    timeout=cfg.timeout,
                    verify_tls=cfg.verify_tls,
                    allow_redirects=cfg.allow_redirects,
                    retries=cfg.retries,
                ),
                "info": gather_info(
                    args.target,
                    timeout=cfg.timeout,
                    verify_tls=cfg.verify_tls,
                    allow_redirects=cfg.allow_redirects,
                    max_bytes=cfg.max_bytes,
                    retries=cfg.retries,
                ),
                "enum": enumerate_attack_surface(
                    args.target,
                    timeout=cfg.timeout,
                    max_pages=cfg.max_pages,
                    max_bytes=cfg.max_bytes,
                    wordlist_file=args.wordlist,
                    wordlist_category=args.wordlist_category,
                    allow_redirects=cfg.allow_redirects,
                    verify_tls=cfg.verify_tls,
                    retries=cfg.retries,
                    min_interval_ms=cfg.rate_limit_ms,
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
    enum_cmd.add_argument("--timeout", type=float, default=None, help="HTTP timeout in seconds")
    enum_cmd.add_argument("--max-pages", type=int, default=None, help="Max pages to fetch in crawler")
    enum_cmd.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="Max bytes to read per response",
    )
    enum_cmd.add_argument("--follow-redirects", action="store_true", default=None, help="Follow redirects")
    enum_cmd.add_argument("--insecure", action="store_true", default=None, help="Disable TLS cert verification")
    enum_cmd.add_argument("--retries", type=int, default=None, help="Retry count on network errors")
    enum_cmd.add_argument(
        "--rate-limit-ms",
        type=int,
        default=None,
        help="Min interval between requests in ms",
    )
    enum_cmd.add_argument("--wordlist", type=str, default=None, help="Path to custom wordlist file (optional)")
    enum_cmd.add_argument(
        "--wordlist-category",
        choices=("common", "api", "backup", "all"),
        default="common",
        help="Built-in wordlist category when --wordlist is not provided (default: common)",
    )
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
        def _runner() -> dict[str, Any]:
            cfg = _load_scan_config(args)
            return enumerate_attack_surface(
                args.target,
                timeout=cfg.timeout,
                max_pages=cfg.max_pages,
                max_bytes=cfg.max_bytes,
                wordlist_file=args.wordlist,
                wordlist_category=args.wordlist_category,
                allow_redirects=cfg.allow_redirects,
                verify_tls=cfg.verify_tls,
                retries=cfg.retries,
                min_interval_ms=cfg.rate_limit_ms,
                fetch_spa_assets=not args.no_spa_assets,
                max_spa_assets=args.max_spa_assets,
                spa_asset_max_bytes=args.spa_asset_bytes,
            )

        return _run_command(
            args,
            command="enum",
            target=args.target,
            runner=_runner,
        )

    enum_cmd.set_defaults(func=_enum_cmd)

    vuln = subparsers.add_parser("vuln", help="Vulnerability module (week5: skeleton/dry-run)")
    vuln.add_argument("-i", "--input", required=True, help="Input JSON file (from juicechain scan)")
    vuln.add_argument("--dry-run", action="store_true", help="Only derive input points and output stats (no requests)")
    vuln.add_argument("--timeout", type=float, default=None, help="HTTP timeout seconds")
    vuln.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="Max response bytes to read",
    )
    vuln.add_argument("--retries", type=int, default=None, help="Retry times")
    vuln.add_argument(
        "--rate-limit-ms",
        type=int,
        default=None,
        help="Min interval between requests in ms",
    )
    vuln.add_argument("--insecure", action="store_true", default=None, help="Disable TLS verification")
    vuln.add_argument("--follow-redirects", action="store_true", default=None, help="Follow redirects")
    vuln.add_argument("--dom-xss", action="store_true", default=None, help="Enable DOM-XSS verification via Playwright")
    vuln.add_argument("--headed", action="store_true", default=None, help="Run browser in headed mode (for debugging)")
    _add_runtime_options(vuln, allow_output_file=True)

    def _vuln_cmd(args: argparse.Namespace) -> int:
        def _runner() -> dict[str, Any]:
            cfg = _load_scan_config(args)
            raw = _load_json_input(Path(args.input))
            scan_doc = _extract_scan_document(raw)
            if args.dry_run:
                return vuln_dry_run_report(scan_doc, version=_get_version(), config=cfg)
            return scan_vulnerabilities(
                scan_doc,
                version=_get_version(),
                timeout=float(cfg.timeout),
                verify_tls=bool(cfg.verify_tls),
                allow_redirects=bool(cfg.allow_redirects),
                retries=int(cfg.retries),
                min_interval_ms=int(cfg.rate_limit_ms),
                max_bytes=int(cfg.max_bytes),
                enable_dom_xss=bool(cfg.enable_dom_xss),
                dom_xss_headless=not bool(args.headed),
                config=cfg,
            )

        return _run_command(
            args,
            command="vuln",
            target=args.input,
            runner=_runner,
        )

    vuln.set_defaults(func=_vuln_cmd)

    init_cmd = subparsers.add_parser("init", help="Generate a default JuiceChain config template")
    init_cmd.add_argument(
        "-o",
        "--output",
        dest="config_output",
        type=str,
        default="juicechain.toml",
        help="Output config file path (default: juicechain.toml)",
    )
    init_cmd.add_argument("--force", action="store_true", help="Overwrite output file if it already exists")
    _add_runtime_options(init_cmd, allow_output_file=False)

    def _init_cmd(args: argparse.Namespace) -> int:
        def _runner() -> dict[str, Any]:
            out = Path(args.config_output)
            if out.exists() and not args.force:
                raise CliUsageError(f"config file already exists: {out} (use --force to overwrite)")
            out.write_text(default_config_template(), encoding="utf-8")
            return {"output_file": str(out), "overwritten": bool(args.force)}

        return _run_command(
            args,
            command="init",
            target=args.config_output,
            runner=_runner,
        )

    init_cmd.set_defaults(func=_init_cmd)

    report = subparsers.add_parser("report", help="Generate report (Markdown/HTML) from scan JSON")
    report.add_argument("-i", "--input", required=True, help="Input JSON file (from juicechain scan)")
    report.add_argument(
        "--vuln",
        default=None,
        help="Optional vuln JSON file (from juicechain vuln)",
    )
    report.add_argument(
        "-o",
        "--output",
        dest="report_output",
        default=None,
        help="Output report file (default: stdout)",
    )
    report.add_argument(
        "--format",
        choices=("markdown", "html"),
        default="markdown",
        help="Report format (default: markdown)",
    )
    _add_runtime_options(
        report,
        allow_output_file=False,
        include_format=False,
        include_pretty=False,
    )

    def _report_cmd(args: argparse.Namespace) -> int:
        def _runner() -> dict[str, Any]:
            scan_raw = _load_json_input(Path(args.input))
            _extract_scan_document(scan_raw)

            vuln_raw: dict[str, Any] | None = None
            if args.vuln:
                vuln_loaded = _load_json_input(Path(args.vuln))
                _extract_vuln_document(vuln_loaded)
                vuln_raw = vuln_loaded

            out_md = build_scan_report(scan_raw, vuln_raw)
            out_text = markdown_to_html(out_md) if args.format == "html" else out_md

            if args.report_output:
                Path(args.report_output).write_text(out_text, encoding="utf-8")
            return {
                "input_file": args.input,
                "vuln_file": args.vuln,
                "output_file": args.report_output,
                "output_format": args.format,
                "line_count": len(out_text.splitlines()),
                "report": None if args.report_output else out_text,
            }

        return _run_command(
            args,
            command="report",
            target=args.input,
            runner=_runner,
        )

    report.set_defaults(func=_report_cmd)

    pipeline = subparsers.add_parser(
        "pipeline",
        help="Run end-to-end flow: scan -> vuln -> report",
    )
    pipeline.add_argument("-t", "--target", required=True, help="Target URL or host[:port]")
    pipeline.add_argument("--timeout", type=float, default=None, help="HTTP timeout in seconds")
    pipeline.add_argument("--max-pages", type=int, default=None, help="Max pages to fetch in crawler")
    pipeline.add_argument(
        "--max-bytes",
        type=int,
        default=None,
        help="Max bytes to read per response",
    )
    pipeline.add_argument("--follow-redirects", action="store_true", default=None, help="Follow redirects")
    pipeline.add_argument("--insecure", action="store_true", default=None, help="Disable TLS cert verification")
    pipeline.add_argument("--retries", type=int, default=None, help="Retry count on network errors")
    pipeline.add_argument(
        "--rate-limit-ms",
        type=int,
        default=None,
        help="Min interval between requests in ms",
    )
    pipeline.add_argument("--wordlist", type=str, default=None, help="Path to custom wordlist file (optional)")
    pipeline.add_argument(
        "--wordlist-category",
        choices=("common", "api", "backup", "all"),
        default="common",
        help="Built-in wordlist category when --wordlist is not provided (default: common)",
    )
    pipeline.add_argument("--no-spa-assets", action="store_true", help="Disable SPA asset fetching")
    pipeline.add_argument("--max-spa-assets", type=int, default=6, help="Max JS assets to fetch (default: 6)")
    pipeline.add_argument(
        "--spa-asset-bytes",
        type=int,
        default=450_000,
        help="Max bytes per JS asset fetch (default: 450000)",
    )
    pipeline.add_argument("--dom-xss", action="store_true", default=None, help="Enable DOM-XSS verification")
    pipeline.add_argument("--headed", action="store_true", default=None, help="Run browser in headed mode")
    pipeline.add_argument("--dry-run", action="store_true", help="Skip active vuln probes and only derive points")
    pipeline.add_argument(
        "-o",
        "--output",
        dest="report_output",
        default=None,
        help="Output report file (default: stdout)",
    )
    pipeline.add_argument(
        "--format",
        choices=("markdown", "html"),
        default="markdown",
        help="Report format (default: markdown)",
    )
    _add_runtime_options(
        pipeline,
        allow_output_file=False,
        include_format=False,
        include_pretty=False,
    )

    def _pipeline_cmd(args: argparse.Namespace) -> int:
        def _runner() -> dict[str, Any]:
            cfg = _load_scan_config(args)
            cli_version = _get_version()

            scan_doc = {
                "target": args.target,
                "alive": check_http_alive(
                    args.target,
                    timeout=cfg.timeout,
                    verify_tls=cfg.verify_tls,
                    allow_redirects=cfg.allow_redirects,
                    retries=cfg.retries,
                ),
                "info": gather_info(
                    args.target,
                    timeout=cfg.timeout,
                    verify_tls=cfg.verify_tls,
                    allow_redirects=cfg.allow_redirects,
                    max_bytes=cfg.max_bytes,
                    retries=cfg.retries,
                ),
                "enum": enumerate_attack_surface(
                    args.target,
                    timeout=cfg.timeout,
                    max_pages=cfg.max_pages,
                    max_bytes=cfg.max_bytes,
                    wordlist_file=args.wordlist,
                    wordlist_category=args.wordlist_category,
                    allow_redirects=cfg.allow_redirects,
                    verify_tls=cfg.verify_tls,
                    retries=cfg.retries,
                    min_interval_ms=cfg.rate_limit_ms,
                    fetch_spa_assets=not args.no_spa_assets,
                    max_spa_assets=args.max_spa_assets,
                    spa_asset_max_bytes=args.spa_asset_bytes,
                ),
            }

            if args.dry_run:
                vuln_doc = vuln_dry_run_report(scan_doc, version=cli_version, config=cfg)
            else:
                vuln_doc = scan_vulnerabilities(
                    scan_doc,
                    version=cli_version,
                    timeout=float(cfg.timeout),
                    verify_tls=bool(cfg.verify_tls),
                    allow_redirects=bool(cfg.allow_redirects),
                    retries=int(cfg.retries),
                    min_interval_ms=int(cfg.rate_limit_ms),
                    max_bytes=int(cfg.max_bytes),
                    enable_dom_xss=bool(cfg.enable_dom_xss),
                    dom_xss_headless=not bool(args.headed),
                    config=cfg,
                )

            scan_report_input = {
                "meta": {
                    "tool": "juicechain",
                    "version": cli_version,
                    "command": "scan",
                    "timestamp": int(time.time()),
                },
                "data": scan_doc,
            }
            vuln_report_input = {
                "meta": {
                    "tool": "juicechain",
                    "version": cli_version,
                    "command": "vuln",
                    "timestamp": int(time.time()),
                },
                "data": vuln_doc,
            }

            out_md = build_scan_report(scan_report_input, vuln_report_input)
            out_text = markdown_to_html(out_md) if args.format == "html" else out_md
            if args.report_output:
                Path(args.report_output).write_text(out_text, encoding="utf-8")

            scan_errors = _extract_scan_errors(scan_doc)
            vuln_errors = _extract_errors_from_obj(vuln_doc)
            all_errors = normalize_errors(scan_errors + vuln_errors)
            alive_info = scan_doc.get("alive") if isinstance(scan_doc.get("alive"), dict) else {}
            findings = vuln_doc.get("findings") if isinstance(vuln_doc.get("findings"), list) else []

            return {
                "ok": bool(alive_info.get("alive")) and len(all_errors) == 0,
                "errors": all_errors,
                "target": args.target,
                "dry_run": bool(args.dry_run),
                "intermediate_transport": "memory",
                "scan_alive": bool(alive_info.get("alive")),
                "findings_count": len(findings),
                "output_file": args.report_output,
                "output_format": args.format,
                "line_count": len(out_text.splitlines()),
                "report": None if args.report_output else out_text,
            }

        return _run_command(
            args,
            command="pipeline",
            target=args.target,
            runner=_runner,
        )

    pipeline.set_defaults(func=_pipeline_cmd)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
