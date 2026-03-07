from __future__ import annotations

from typing import cast

from juicechain.core.http_client import HttpClient, HttpResponse
from juicechain.core.input_point import InputPoint
from juicechain.core.vulnerability import check_sqli_error


class BaselineSqliClient:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.calls: list[tuple[str, str, dict[str, str], dict[str, str]]] = []

    def request(self, method: str, url: str, **kwargs: object) -> HttpResponse:
        params = kwargs.get("params")
        headers = kwargs.get("headers")
        query = dict(params) if isinstance(params, dict) else {}
        sent_headers = dict(headers) if isinstance(headers, dict) else {}
        self.calls.append((method, url, query, sent_headers))

        if self.mode == "query_baseline_500":
            if query.get("q") == "juicechain_probe":
                return HttpResponse(
                    ok=True,
                    url=url,
                    status_code=500,
                    headers={"Content-Type": "application/json"},
                    body=b'{"error":"missing required parameter"}',
                    response_time_ms=5,
                    error=None,
                )
            return HttpResponse(
                ok=True,
                url=url,
                status_code=500,
                headers={"Content-Type": "application/json"},
                body=b'{"error":"SQLITE_ERROR: syntax error"}',
                response_time_ms=5,
                error=None,
            )

        if self.mode == "query_injection_finds_error":
            if query.get("q") == "juicechain_probe":
                return HttpResponse(
                    ok=True,
                    url=url,
                    status_code=200,
                    headers={"Content-Type": "application/json"},
                    body=b'{"items":[]}',
                    response_time_ms=5,
                    error=None,
                )
            if "'" in str(query.get("q", "")):
                return HttpResponse(
                    ok=True,
                    url=url,
                    status_code=500,
                    headers={"Content-Type": "application/json"},
                    body=b'{"error":"SQLITE_ERROR: syntax error"}',
                    response_time_ms=5,
                    error=None,
                )
            return HttpResponse(
                ok=True,
                url=url,
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=b'{"items":[]}',
                response_time_ms=5,
                error=None,
            )

        if self.mode == "header_baseline_500":
            if "Referer" not in sent_headers:
                return HttpResponse(
                    ok=True,
                    url=url,
                    status_code=500,
                    headers={"Content-Type": "text/html"},
                    body=b'<html>missing required parameter</html>',
                    response_time_ms=5,
                    error=None,
                )
            return HttpResponse(
                ok=True,
                url=url,
                status_code=500,
                headers={"Content-Type": "text/html"},
                body=b'<html>SQLITE_ERROR: syntax error</html>',
                response_time_ms=5,
                error=None,
            )

        raise AssertionError(f"unexpected mode: {self.mode}")

    def close(self) -> None:
        return None



def test_sqli_error_query_baseline_500_returns_none() -> None:
    point = InputPoint(method="GET", path="/rest/user/security-question", location="query", param="q")
    client = BaselineSqliClient(mode="query_baseline_500")

    finding = check_sqli_error(
        base="http://example.test",
        pt=point,
        client=cast(HttpClient, client),
        timeout=1.0,
        max_bytes=50_000,
        json_field_group={},
    )

    assert finding is None
    assert len(client.calls) == 1



def test_sqli_error_query_baseline_clean_injection_error_returns_finding() -> None:
    point = InputPoint(method="GET", path="/rest/products/search", location="query", param="q")
    client = BaselineSqliClient(mode="query_injection_finds_error")

    finding = check_sqli_error(
        base="http://example.test",
        pt=point,
        client=cast(HttpClient, client),
        timeout=1.0,
        max_bytes=50_000,
        json_field_group={},
    )

    assert finding is not None
    assert finding.type == "SQLI_ERROR"
    assert len(client.calls) == 2



def test_sqli_error_header_baseline_500_returns_none() -> None:
    point = InputPoint(method="GET", path="/rest/user/security-question", location="header", param="Referer")
    client = BaselineSqliClient(mode="header_baseline_500")

    finding = check_sqli_error(
        base="http://example.test",
        pt=point,
        client=cast(HttpClient, client),
        timeout=1.0,
        max_bytes=50_000,
        json_field_group={},
    )

    assert finding is None
    assert len(client.calls) == 1
