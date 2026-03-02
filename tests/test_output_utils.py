import time

from juicechain.utils.output import build_cli_payload, render_payload


def test_render_payload_json_contains_schema():
    payload = build_cli_payload(
        command="alive",
        version="test",
        target="http://example.test",
        started_at=time.perf_counter(),
        data={"alive": True, "status_code": 200, "response_time_ms": 12},
        errors=[],
        ok=True,
    )
    out = render_payload(payload, fmt="json", pretty=False)
    assert '"schema": "juicechain.cli.result/v1"' in out
    assert '"command": "alive"' in out


def test_render_payload_table_contains_field_header():
    payload = build_cli_payload(
        command="alive",
        version="test",
        target="http://example.test",
        started_at=time.perf_counter(),
        data={"alive": True, "status_code": 200, "response_time_ms": 12},
        errors=[],
        ok=True,
    )
    out = render_payload(payload, fmt="table", pretty=False)
    assert "Field" in out
    assert "command" in out
