from __future__ import annotations

import argparse
from importlib.metadata import version, PackageNotFoundError


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

    #placeholder: report
    report = subparsers.add_parser("report", help="Generate report (placeholder)")
    report.set_defaults(func=lambda _args: print("[report] placeholder: not implemented yet"))
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
    return 0

    
if __name__ == "__main__":
    raise SystemExit(main())
