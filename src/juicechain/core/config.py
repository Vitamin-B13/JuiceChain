from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


def _load_toml(path: str) -> dict[str, Any]:
    try:
        import tomllib  # py311+
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[import-not-found]  # py310 fallback
        except ModuleNotFoundError as e:
            raise RuntimeError(
                "TOML parser not available. On Python 3.10, install 'tomli'."
            ) from e

    p = Path(path)
    with p.open("rb") as f:
        data = tomllib.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"config root must be object: {path}")
    return data


def _as_float(v: Any, *, key: str) -> float:
    if isinstance(v, bool):
        raise ValueError(f"{key} must be float, got bool")
    if isinstance(v, (int, float)):
        return float(v)
    raise ValueError(f"{key} must be float")


def _as_int(v: Any, *, key: str) -> int:
    if isinstance(v, bool):
        raise ValueError(f"{key} must be int, got bool")
    if isinstance(v, int):
        return v
    raise ValueError(f"{key} must be int")


def _as_bool(v: Any, *, key: str) -> bool:
    if isinstance(v, bool):
        return v
    raise ValueError(f"{key} must be bool")


def _as_str_list(v: Any, *, key: str) -> list[str]:
    if not isinstance(v, list):
        raise ValueError(f"{key} must be list[str]")
    out: list[str] = []
    for i, item in enumerate(v):
        if not isinstance(item, str):
            raise ValueError(f"{key}[{i}] must be string")
        s = item.strip()
        if s:
            out.append(s)
    return out


def _as_dict_list(v: Any, *, key: str) -> list[dict[str, Any]]:
    if not isinstance(v, list):
        raise ValueError(f"{key} must be list[dict]")
    out: list[dict[str, Any]] = []
    for i, item in enumerate(v):
        if not isinstance(item, Mapping):
            raise ValueError(f"{key}[{i}] must be object")
        out.append(dict(item))
    return out


@dataclass
class ScanConfig:
    timeout: float = 3.0
    max_bytes: int = 300_000
    max_pages: int = 30
    verify_tls: bool = True
    allow_redirects: bool = False
    retries: int = 0
    rate_limit_ms: int = 0

    # Vulnerability checks
    enable_xss: bool = True
    enable_sqli_error: bool = True
    enable_sqli_boolean: bool = True
    enable_dom_xss: bool = False

    # Extra user-defined input points
    extra_input_points: list[dict[str, Any]] = field(default_factory=list)

    # Custom JSON POST endpoint keyword heuristics
    login_keywords: list[str] = field(default_factory=lambda: ["login", "signin", "auth"])
    register_keywords: list[str] = field(default_factory=lambda: ["register", "signup"])

    @classmethod
    def from_file(cls, path: str) -> "ScanConfig":
        data = _load_toml(path)
        scan = data.get("scan")
        vuln = data.get("vuln")
        if scan is None:
            scan = {}
        if vuln is None:
            vuln = {}
        if not isinstance(scan, Mapping):
            raise ValueError("[scan] must be object")
        if not isinstance(vuln, Mapping):
            raise ValueError("[vuln] must be object")

        cfg = cls()

        # scan section
        if "timeout" in scan:
            cfg.timeout = _as_float(scan["timeout"], key="scan.timeout")
        if "max_bytes" in scan:
            cfg.max_bytes = _as_int(scan["max_bytes"], key="scan.max_bytes")
        if "max_pages" in scan:
            cfg.max_pages = _as_int(scan["max_pages"], key="scan.max_pages")
        if "verify_tls" in scan:
            cfg.verify_tls = _as_bool(scan["verify_tls"], key="scan.verify_tls")
        if "allow_redirects" in scan:
            cfg.allow_redirects = _as_bool(scan["allow_redirects"], key="scan.allow_redirects")
        if "retries" in scan:
            cfg.retries = _as_int(scan["retries"], key="scan.retries")
        if "rate_limit_ms" in scan:
            cfg.rate_limit_ms = _as_int(scan["rate_limit_ms"], key="scan.rate_limit_ms")

        # vuln section
        if "enable_xss" in vuln:
            cfg.enable_xss = _as_bool(vuln["enable_xss"], key="vuln.enable_xss")
        if "enable_sqli_error" in vuln:
            cfg.enable_sqli_error = _as_bool(vuln["enable_sqli_error"], key="vuln.enable_sqli_error")
        if "enable_sqli_boolean" in vuln:
            cfg.enable_sqli_boolean = _as_bool(vuln["enable_sqli_boolean"], key="vuln.enable_sqli_boolean")
        if "enable_dom_xss" in vuln:
            cfg.enable_dom_xss = _as_bool(vuln["enable_dom_xss"], key="vuln.enable_dom_xss")
        if "login_keywords" in vuln:
            cfg.login_keywords = _as_str_list(vuln["login_keywords"], key="vuln.login_keywords")
        if "register_keywords" in vuln:
            cfg.register_keywords = _as_str_list(vuln["register_keywords"], key="vuln.register_keywords")

        # top-level arrays (sample-friendly)
        if "extra_input_points" in data:
            cfg.extra_input_points = _as_dict_list(data["extra_input_points"], key="extra_input_points")
        if "extra_input_points" in vuln:
            cfg.extra_input_points = _as_dict_list(vuln["extra_input_points"], key="vuln.extra_input_points")

        return cfg

    @classmethod
    def from_cli_args(cls, args: argparse.Namespace) -> "ScanConfig":
        cfg = cls()
        config_path = getattr(args, "config", None)
        if isinstance(config_path, str) and config_path.strip():
            cfg = cls.from_file(config_path.strip())

        # CLI overrides config.
        timeout = getattr(args, "timeout", None)
        if timeout is not None:
            cfg.timeout = float(timeout)

        max_bytes = getattr(args, "max_bytes", None)
        if max_bytes is not None:
            cfg.max_bytes = int(max_bytes)

        max_pages = getattr(args, "max_pages", None)
        if max_pages is not None:
            cfg.max_pages = int(max_pages)

        retries = getattr(args, "retries", None)
        if retries is not None:
            cfg.retries = int(retries)

        rate_limit_ms = getattr(args, "rate_limit_ms", None)
        if rate_limit_ms is not None:
            cfg.rate_limit_ms = int(rate_limit_ms)

        follow_redirects = getattr(args, "follow_redirects", None)
        if follow_redirects is not None:
            cfg.allow_redirects = bool(follow_redirects)

        insecure = getattr(args, "insecure", None)
        if insecure is not None:
            cfg.verify_tls = not bool(insecure)

        dom_xss = getattr(args, "dom_xss", None)
        if dom_xss is not None:
            cfg.enable_dom_xss = bool(dom_xss)

        return cfg


def default_config_template() -> str:
    return """# JuiceChain configuration (TOML)
# CLI flags override config values.

[scan]
timeout = 3.0
max_bytes = 300000
max_pages = 30
verify_tls = true
allow_redirects = false
retries = 0
rate_limit_ms = 0

[vuln]
enable_xss = true
enable_sqli_error = true
enable_sqli_boolean = true
enable_dom_xss = false
login_keywords = ["login", "signin", "auth"]
register_keywords = ["register", "signup"]

[[extra_input_points]]
method = "GET"
path = "/search"
location = "query"
param = "q"
"""
