from __future__ import annotations
from juicechain.core.vulnerability import vuln_dry_run_report


import argparse
import json
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from juicechain.core.alive import check_http_alive
from juicechain.core.info_gather import gather_info
from juicechain.core.enumeration import enumerate_attack_surface


def _get_version() -> str:
    try:
        return version("juicechain")
    except PackageNotFoundError:
        return "0.0.0"


def _dump(obj: Any, *, pretty: bool) -> str:
    if pretty:
        return json.dumps(obj, ensure_ascii=False, indent=2)
    return json.dumps(obj, ensure_ascii=False)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="juicechain",
        description="JuiceChain: lightweight recon & enumeration toolchain (authorized targets only)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_get_version()}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan: pipeline = alive + info + enum
    scan = subparsers.add_parser("scan", help="Run pipeline: alive -> info -> enum")
    scan.add_argument("-t", "--target", required=True, help="Target URL or host[:port]")
    scan.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds (default: 3.0)")
    scan.add_argument("--max-pages", type=int, default=30, help="Max pages to fetch in crawler (default: 30)")
    scan.add_argument("--max-bytes", type=int, default=300_000, help="Max bytes to read per response (default: 300000)")
    scan.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: false)")
    scan.add_argument("--insecure", action="store_true", help="Disable TLS cert verification (default: false)")
    scan.add_argument("--retries", type=int, default=0, help="Retry count on network errors (default: 0)")
    scan.add_argument("--rate-limit-ms", type=int, default=0, help="Min interval between requests in ms (default: 0)")
    scan.add_argument("--wordlist", type=str, default=None, help="Path to custom wordlist file (optional)")
    scan.add_argument("--no-spa-assets", action="store_true", help="Disable SPA asset fetching (default: false)")
    scan.add_argument("--max-spa-assets", type=int, default=6, help="Max JS assets to fetch (default: 6)")
    scan.add_argument("--spa-asset-bytes", type=int, default=450_000, help="Max bytes per JS asset fetch (default: 450000)")
    scan.add_argument("-o", "--output", type=str, default=None, help="Write JSON result to file")
    scan.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    def _scan_cmd(args: argparse.Namespace) -> None:
        t0 = time.time()
        verify_tls = not args.insecure
        allow_redirects = bool(args.follow_redirects)

        alive_res = check_http_alive(
            args.target,
            timeout=args.timeout,
            verify_tls=verify_tls,
            allow_redirects=allow_redirects,
            retries=args.retries,
        )
        info_res = gather_info(
            args.target,
            timeout=args.timeout,
            verify_tls=verify_tls,
            allow_redirects=allow_redirects,
            max_bytes=args.max_bytes,
            retries=args.retries,
        )
        enum_res = enumerate_attack_surface(
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
        )

        out = {
            "meta": {
                "tool": "juicechain",
                "version": _get_version(),
                "timestamp": int(time.time()),
                "duration_ms": int(round((time.time() - t0) * 1000)),
            },
            "target": args.target,
            "alive": alive_res,
            "info": info_res,
            "enum": enum_res,
        }

        s = _dump(out, pretty=args.pretty)
        if args.output:
            Path(args.output).write_text(s, encoding="utf-8")
        else:
            print(s)

    scan.set_defaults(func=_scan_cmd)

    # alive
    alive = subparsers.add_parser("alive", help="Check target liveness via HTTP")
    alive.add_argument("-t", "--target", required=True, help="Target URL or host[:port]")
    alive.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds (default: 3.0)")
    alive.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: false)")
    alive.add_argument("--insecure", action="store_true", help="Disable TLS cert verification (default: false)")
    alive.add_argument("--retries", type=int, default=0, help="Retry count on network errors (default: 0)")
    alive.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    def _alive_cmd(args: argparse.Namespace) -> None:
        res = check_http_alive(
            args.target,
            timeout=args.timeout,
            verify_tls=not args.insecure,
            allow_redirects=bool(args.follow_redirects),
            retries=args.retries,
        )
        print(_dump(res, pretty=args.pretty))

    alive.set_defaults(func=_alive_cmd)

    # info
    info = subparsers.add_parser("info", help="Passive info gathering (headers/title/robots + basic audit)")
    info.add_argument("-t", "--target", required=True, help="Target URL or host[:port]")
    info.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds (default: 3.0)")
    info.add_argument("--max-bytes", type=int, default=256_000, help="Max bytes to read per response (default: 256000)")
    info.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: false)")
    info.add_argument("--insecure", action="store_true", help="Disable TLS cert verification (default: false)")
    info.add_argument("--retries", type=int, default=0, help="Retry count on network errors (default: 0)")
    info.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    def _info_cmd(args: argparse.Namespace) -> None:
        res = gather_info(
            args.target,
            timeout=args.timeout,
            verify_tls=not args.insecure,
            allow_redirects=bool(args.follow_redirects),
            max_bytes=args.max_bytes,
            retries=args.retries,
        )
        print(_dump(res, pretty=args.pretty))

    info.set_defaults(func=_info_cmd)

    # enum
    enum_cmd = subparsers.add_parser("enum", help="Attack surface enumeration (crawler + content discovery)")
    enum_cmd.add_argument("-t", "--target", required=True, help="Target URL or host[:port]")
    enum_cmd.add_argument("--timeout", type=float, default=3.0, help="HTTP timeout in seconds (default: 3.0)")
    enum_cmd.add_argument("--max-pages", type=int, default=30, help="Max pages to fetch in crawler (default: 30)")
    enum_cmd.add_argument("--max-bytes", type=int, default=300_000, help="Max bytes to read per response (default: 300000)")
    enum_cmd.add_argument("--follow-redirects", action="store_true", help="Follow redirects (default: false)")
    enum_cmd.add_argument("--insecure", action="store_true", help="Disable TLS cert verification (default: false)")
    enum_cmd.add_argument("--retries", type=int, default=0, help="Retry count on network errors (default: 0)")
    enum_cmd.add_argument("--rate-limit-ms", type=int, default=0, help="Min interval between requests in ms (default: 0)")
    enum_cmd.add_argument("--wordlist", type=str, default=None, help="Path to custom wordlist file (optional)")
    enum_cmd.add_argument("--no-spa-assets", action="store_true", help="Disable SPA asset fetching (default: false)")
    enum_cmd.add_argument("--max-spa-assets", type=int, default=6, help="Max JS assets to fetch (default: 6)")
    enum_cmd.add_argument("--spa-asset-bytes", type=int, default=450_000, help="Max bytes per JS asset fetch (default: 450000)")
    enum_cmd.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    def _enum_cmd(args: argparse.Namespace) -> None:
        res = enumerate_attack_surface(
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
        )
        print(_dump(res, pretty=args.pretty))

    enum_cmd.set_defaults(func=_enum_cmd)

        # vuln (week5 skeleton): derive input points + dry-run output
    vuln = subparsers.add_parser("vuln", help="Vulnerability module (week5: skeleton/dry-run)")
    vuln.add_argument("-i", "--input", required=True, help="Input JSON file (from juicechain scan)")
    vuln.add_argument("--dry-run", action="store_true", help="Only derive input points and output stats (no requests)")
    vuln.add_argument("-o", "--output", type=str, default=None, help="Write JSON result to file")
    vuln.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")

    def _vuln_cmd(args: argparse.Namespace) -> None:
        p = Path(args.input)
        scan_doc = json.loads(p.read_text(encoding="utf-8"))

        # Step 5.1: only dry-run is meaningful; non-dry-run kept as placeholder
        out = vuln_dry_run_report(scan_doc, version=_get_version())
        if not args.dry_run:
            out["meta"]["mode"] = "placeholder"

        s = _dump(out, pretty=args.pretty)
        if args.output:
            Path(args.output).write_text(s, encoding="utf-8")
        else:
            print(s)

    vuln.set_defaults(func=_vuln_cmd)

    # report（保持你 v0.5 那份不变即可）
    report = subparsers.add_parser("report", help="Generate a Markdown report from scan JSON")
    report.add_argument("-i", "--input", required=True, help="Input JSON file (from juicechain scan)")
    report.add_argument("-o", "--output", default=None, help="Output markdown file (default: stdout)")

    def _report_cmd(args: argparse.Namespace) -> None:
        p = Path(args.input)
        data = json.loads(p.read_text(encoding="utf-8"))

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

        out_md = "\n".join(md_lines)
        if args.output:
            Path(args.output).write_text(out_md, encoding="utf-8")
        else:
            sys.stdout.write(out_md)

    report.set_defaults(func=_report_cmd)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())