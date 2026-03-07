from __future__ import annotations

from juicechain.core.http_client import HttpResponse
from juicechain.core.input_point import InputPoint
from juicechain.plugins.sqli_time import Plugin


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def advance_ms(self, ms: int) -> None:
        self.now += ms / 1000.0


class FakeClient:
    def __init__(self, clock: FakeClock, inject_delay_ms: int) -> None:
        self.clock = clock
        self.inject_delay_ms = inject_delay_ms

    def request(self, method, url, **kwargs):
        del method, url
        params = kwargs.get("params") or {}
        json_data = kwargs.get("json_data") or {}
        data = kwargs.get("data") or {}

        value = ""
        if params:
            value = str(next(iter(params.values())))
        elif json_data:
            value = str(next(iter(json_data.values())))
        elif data:
            value = str(next(iter(data.values())))

        is_injection = "SLEEP(5)" in value or "pg_sleep(5)" in value or "WAITFOR DELAY" in value
        delay_ms = self.inject_delay_ms if is_injection else 200
        self.clock.advance_ms(delay_ms)

        return HttpResponse(
            ok=True,
            url="http://example.test/search",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body=b"{}",
            response_time_ms=delay_ms,
            error=None,
        )


def test_sqli_time_finds_delay(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr("juicechain.plugins.sqli_time.time.monotonic", clock.monotonic)
    client = FakeClient(clock=clock, inject_delay_ms=6000)
    plugin = Plugin()
    point = InputPoint(method="GET", path="/api/search", location="query", param="q")

    finding = plugin.check(
        base="http://example.test",
        point=point,
        client=client,
        timeout=1.0,
        max_bytes=50_000,
    )

    assert finding is not None
    assert finding.vuln_type == "SQLI_TIME"


def test_sqli_time_ignores_uniform_latency(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr("juicechain.plugins.sqli_time.time.monotonic", clock.monotonic)
    client = FakeClient(clock=clock, inject_delay_ms=200)
    plugin = Plugin()
    point = InputPoint(method="GET", path="/api/search", location="query", param="q")

    finding = plugin.check(
        base="http://example.test",
        point=point,
        client=client,
        timeout=1.0,
        max_bytes=50_000,
    )

    assert finding is None
