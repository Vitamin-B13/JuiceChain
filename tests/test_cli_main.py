from pathlib import Path
from types import SimpleNamespace

import pytest
import juicechain.cli.main as cli

from juicechain.core.config import ScanConfig
from juicechain.cli.main import CliUsageError, _emit_payload, _extract_scan_document, _load_json_input, build_parser


def test_load_json_input_missing_file():
    with pytest.raises(CliUsageError, match="input file not found"):
        _load_json_input(Path("does-not-exist.json"))


def test_load_json_input_invalid_json(monkeypatch):
    def _bad_read_text(self, encoding="utf-8"):
        del self, encoding
        return "{invalid json}"

    monkeypatch.setattr(Path, "read_text", _bad_read_text)

    with pytest.raises(CliUsageError, match="invalid JSON"):
        _load_json_input(Path("scan.json"))


def test_extract_scan_document_accepts_legacy_shape():
    doc = {"alive": {}, "info": {}, "enum": {}}
    out = _extract_scan_document(doc)
    assert out is doc


def test_extract_scan_document_accepts_cli_payload_shape():
    doc = {
        "meta": {"command": "scan"},
        "data": {"alive": {}, "info": {}, "enum": {}},
    }
    out = _extract_scan_document(doc)
    assert out == doc["data"]


def test_emit_payload_output_file_is_pretty_json(tmp_path):
    output_file = tmp_path / "out.json"
    args = SimpleNamespace(output=str(output_file), pretty=False, format="json")
    payload = {"meta": {"command": "scan"}, "ok": True, "target": "x", "data": {}, "errors": []}

    _emit_payload(args, payload)
    text = output_file.read_text(encoding="utf-8")

    assert "\n" in text
    assert '  "meta"' in text


def test_scan_wordlist_category_arg():
    parser = build_parser()
    args = parser.parse_args(["scan", "-t", "http://example.test", "--wordlist-category", "api"])
    assert args.wordlist_category == "api"


def test_scan_api_subpath_probe_args():
    parser = build_parser()
    args = parser.parse_args(
        [
            "scan",
            "-t",
            "http://example.test",
            "--no-api-subpath-probe",
            "--max-api-subpath-probes",
            "12",
        ]
    )
    assert args.no_api_subpath_probe is True
    assert args.max_api_subpath_probes == 12


def test_enum_wordlist_category_default():
    parser = build_parser()
    args = parser.parse_args(["enum", "-t", "http://example.test"])
    assert args.wordlist_category == "common"


def test_enum_api_subpath_probe_defaults():
    parser = build_parser()
    args = parser.parse_args(["enum", "-t", "http://example.test"])
    assert args.no_api_subpath_probe is False
    assert args.max_api_subpath_probes == 200


def test_init_command_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["init"])
    assert args.config_output == "juicechain.toml"
    assert args.force is False


def test_report_command_accepts_vuln_and_html_format():
    parser = build_parser()
    args = parser.parse_args(
        ["report", "-i", "scan.json", "--vuln", "vuln.json", "--format", "html", "-o", "report.html"]
    )
    assert args.vuln == "vuln.json"
    assert args.format == "html"
    assert args.report_output == "report.html"


def test_pipeline_command_parser_defaults():
    parser = build_parser()
    args = parser.parse_args(["pipeline", "-t", "http://example.test"])
    assert args.format == "markdown"
    assert args.wordlist_category == "common"
    assert args.max_api_subpath_probes == 200
    assert args.report_output is None


def test_vuln_output_adds_spa_dom_xss_warning(monkeypatch):
    parser = build_parser()
    args = parser.parse_args(["vuln", "-i", "scan.json", "--dry-run"])

    scan_doc = {
        "target": "http://example.test",
        "alive": {},
        "info": {},
        "enum": {"crawler": {"spa": {"routes_from_assets": ["/#/search"]}}},
    }
    captured: dict[str, object] = {}

    monkeypatch.setattr(cli, "_load_scan_config", lambda _args: ScanConfig(enable_dom_xss=False))
    monkeypatch.setattr(cli, "_load_json_input", lambda _path: {"meta": {"command": "scan"}, "data": scan_doc})
    monkeypatch.setattr(cli, "vuln_dry_run_report", lambda *args, **kwargs: {"findings": [], "errors": []})

    def _fake_run_command(_args, **kwargs):
        captured["data"] = kwargs["runner"]()
        return 0

    monkeypatch.setattr(cli, "_run_command", _fake_run_command)

    rc = args.func(args)
    assert rc == 0
    data = captured["data"]
    assert isinstance(data, dict)
    assert "warnings" in data
    assert any("--dom-xss" in str(item) for item in data["warnings"])


def test_pipeline_output_adds_spa_dom_xss_warning(monkeypatch):
    parser = build_parser()
    args = parser.parse_args(["pipeline", "-t", "http://example.test", "--dry-run"])

    captured: dict[str, object] = {}

    monkeypatch.setattr(cli, "_load_scan_config", lambda _args: ScanConfig(enable_dom_xss=False))
    monkeypatch.setattr(cli, "_get_version", lambda: "test")
    monkeypatch.setattr(cli, "check_http_alive", lambda *args, **kwargs: {"alive": True})
    monkeypatch.setattr(cli, "gather_info", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        cli,
        "enumerate_attack_surface",
        lambda *args, **kwargs: {"crawler": {"spa": {"routes_from_assets": ["/#/login"]}}, "errors": []},
    )
    monkeypatch.setattr(cli, "vuln_dry_run_report", lambda *args, **kwargs: {"findings": [], "errors": []})
    monkeypatch.setattr(cli, "build_scan_report", lambda *args, **kwargs: "# report")

    def _fake_run_command(_args, **kwargs):
        captured["data"] = kwargs["runner"]()
        return 0

    monkeypatch.setattr(cli, "_run_command", _fake_run_command)

    rc = args.func(args)
    assert rc == 0
    data = captured["data"]
    assert isinstance(data, dict)
    assert "warnings" in data
    assert any("--dom-xss" in str(item) for item in data["warnings"])
