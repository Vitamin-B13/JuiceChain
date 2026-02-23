from __future__ import annotations

import argparse
import json
from importlib.metadata import PackageNotFoundError, version

from juicechain.core.alive import check_http_alive
from juicechain.core.info_gather import gather_info


def _get_version() -> str:
    try:
        return version("juicechain")
    except PackageNotFoundError:
        return "0.0.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="juicechain",
        description="JuiceChain: Pentest automation toolchain for OWASP Juice Shop",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # placeholder: scan
    scan = subparsers.add_parser("scan", help="Run scanning phase (placeholder)")
    scan.set_defaults(func=lambda _args: print("[scan] placeholder: not implemented yet"))

    # placeholder: report
    report = subparsers.add_parser("report", help="Generate report (placeholder)")
    report.set_defaults(func=lambda _args: print("[report] placeholder: not implemented yet"))

    # alive: http liveness check
    alive = subparsers.add_parser("alive", help="Check target liveness via HTTP")
    alive.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target URL or host[:port], e.g. http://localhost:3000 or 127.0.0.1:3000",
    )
    alive.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="HTTP timeout in seconds (default: 3.0)",
    )

    def _alive_cmd(args: argparse.Namespace) -> None:
        res = check_http_alive(args.target, timeout=args.timeout)
        print(json.dumps(res, ensure_ascii=False))

    alive.set_defaults(func=_alive_cmd)

    # info: passive info gathering
    info = subparsers.add_parser("info", help="Passive info gathering (headers/title/robots.txt)")
    info.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target URL or host[:port], e.g. http://localhost:3000 or 127.0.0.1:3000",
    )
    info.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="HTTP timeout in seconds (default: 3.0)",
    )
    info.add_argument(
        "--max-bytes",
        type=int,
        default=256_000,
        help="Max bytes to read per response (default: 256000)",
    )
    info.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    def _info_cmd(args: argparse.Namespace) -> None:
        res = gather_info(args.target, timeout=args.timeout, max_bytes=args.max_bytes)
        if args.pretty:
            print(json.dumps(res, ensure_ascii=False, indent=2))
        else:
            print(json.dumps(res, ensure_ascii=False))

    info.set_defaults(func=_info_cmd)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())