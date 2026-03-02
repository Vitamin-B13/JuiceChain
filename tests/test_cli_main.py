from pathlib import Path

import pytest

from juicechain.cli.main import _load_json_input


def test_load_json_input_missing_file():
    with pytest.raises(SystemExit, match="input file not found"):
        _load_json_input(Path("does-not-exist.json"))


def test_load_json_input_invalid_json(monkeypatch):
    def _bad_read_text(self, encoding="utf-8"):
        del self, encoding
        return "{invalid json}"

    monkeypatch.setattr(Path, "read_text", _bad_read_text)

    with pytest.raises(SystemExit, match="invalid JSON"):
        _load_json_input(Path("scan.json"))
