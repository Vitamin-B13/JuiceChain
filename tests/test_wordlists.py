from __future__ import annotations

import pytest

from juicechain.core import enumeration as enum


def test_default_wordlist_common_loads_builtin_file():
    wl = enum.default_wordlist()
    assert len(wl) >= 50
    assert "/admin" in wl
    assert "/api" in wl
    assert "/robots.txt" in wl


def test_default_wordlist_category_specific_and_all():
    wl_api = enum.default_wordlist("api")
    wl_backup = enum.default_wordlist("backup")
    wl_all = enum.default_wordlist("all")

    assert "/api/v1" in wl_api
    assert "/graphql" in wl_api
    assert "/backup.sql" in wl_backup
    assert "/db.sqlite3" in wl_backup
    assert "/api/v1" in wl_all
    assert "/backup.sql" in wl_all
    assert len(wl_all) >= len(enum.default_wordlist("common"))


def test_default_wordlist_invalid_category_raises():
    with pytest.raises(ValueError):
        enum.default_wordlist("unknown")


def test_custom_wordlist_file_keeps_priority_over_category(monkeypatch, tmp_path):
    custom = tmp_path / "custom.txt"
    custom.write_text("secret\n/admin\nsecret\n", encoding="utf-8")

    monkeypatch.setattr(enum, "normalize_target_base", lambda target: "http://example.test")
    monkeypatch.setattr(
        enum,
        "crawl_site",
        lambda *args, **kwargs: {
            "pages_fetched": [],
            "hash_routes": [],
            "spa": {"routes_from_assets": []},
            "errors": [],
        },
    )

    captured: dict[str, list[str]] = {}

    def _fake_dir_bruteforce(base, paths, **kwargs):
        del base, kwargs
        captured["paths"] = list(paths)
        return {
            "findings_server_endpoints": [],
            "findings_spa_routes": [],
            "findings_fallback_noise": [],
            "errors": [],
        }

    monkeypatch.setattr(enum, "dir_bruteforce", _fake_dir_bruteforce)

    enum.enumerate_attack_surface(
        "http://example.test",
        wordlist_file=str(custom),
        wordlist_category="backup",
    )
    assert captured["paths"] == ["/secret", "/admin"]
