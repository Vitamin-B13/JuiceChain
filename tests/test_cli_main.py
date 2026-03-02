from pathlib import Path

import pytest

from juicechain.cli.main import CliUsageError, _extract_scan_document, _load_json_input


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
