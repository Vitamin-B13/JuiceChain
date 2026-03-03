from __future__ import annotations

from types import SimpleNamespace

from juicechain.core.config import ScanConfig, default_config_template


def test_scan_config_from_file_parses_toml(tmp_path):
    p = tmp_path / "cfg.toml"
    p.write_text(
        """
[scan]
timeout = 5.0
max_bytes = 123456
max_pages = 50
verify_tls = false
allow_redirects = true
retries = 2
rate_limit_ms = 120

[vuln]
enable_dom_xss = true
enable_xss = false
enable_sqli_error = true
enable_auth_bypass = false
enable_sqli_boolean = false
login_keywords = ["login", "session"]
register_keywords = ["register", "signup", "join"]

[[extra_input_points]]
method = "GET"
path = "/search"
location = "query"
param = "q"
""",
        encoding="utf-8",
    )

    cfg = ScanConfig.from_file(str(p))
    assert cfg.timeout == 5.0
    assert cfg.max_bytes == 123456
    assert cfg.max_pages == 50
    assert cfg.verify_tls is False
    assert cfg.allow_redirects is True
    assert cfg.retries == 2
    assert cfg.rate_limit_ms == 120
    assert cfg.enable_dom_xss is True
    assert cfg.enable_xss is False
    assert cfg.enable_sqli_error is True
    assert cfg.enable_auth_bypass is False
    assert cfg.enable_sqli_boolean is False
    assert "session" in cfg.login_keywords
    assert "join" in cfg.register_keywords
    assert cfg.extra_input_points and cfg.extra_input_points[0]["path"] == "/search"


def test_scan_config_from_cli_args_priority_cli_over_file_over_default(tmp_path):
    p = tmp_path / "cfg.toml"
    p.write_text(
        """
[scan]
timeout = 6.0
retries = 1
verify_tls = false
allow_redirects = true
""",
        encoding="utf-8",
    )

    args = SimpleNamespace(
        config=str(p),
        timeout=2.5,
        max_bytes=None,
        max_pages=None,
        retries=3,
        rate_limit_ms=None,
        follow_redirects=None,
        insecure=None,
        dom_xss=None,
    )
    cfg = ScanConfig.from_cli_args(args)
    assert cfg.timeout == 2.5  # CLI overrides file
    assert cfg.retries == 3  # CLI overrides file
    assert cfg.verify_tls is False  # from file
    assert cfg.allow_redirects is True  # from file
    assert cfg.max_pages == 30  # default


def test_default_config_template_contains_sections():
    t = default_config_template()
    assert "[scan]" in t
    assert "[vuln]" in t
    assert "[[extra_input_points]]" in t
