from pathlib import Path
from types import SimpleNamespace

import pytest

from juicechain.cli.main import CliUsageError, _emit_payload, _extract_scan_document, _load_json_input


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
