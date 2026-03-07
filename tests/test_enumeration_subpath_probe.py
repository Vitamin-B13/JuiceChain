from __future__ import annotations

from typing import cast
from urllib.parse import urlparse

from juicechain.core.enumeration import probe_api_subpaths
from juicechain.core.http_client import HttpClient, HttpResponse, body_signature


class FakeProbeClient:
    def __init__(self, responses: dict[tuple[str, tuple[tuple[str, str], ...]], HttpResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, tuple[tuple[str, str], ...]]] = []

    def request(self, method: str, url: str, **kwargs: object) -> HttpResponse:
        assert method == "GET"
        parsed = urlparse(url)
        params = kwargs.get("params")
        sent_params = tuple(sorted(dict(params).items())) if isinstance(params, dict) else ()
        key = (parsed.path, sent_params)
        self.calls.append(key)
        if key in self.responses:
            return self.responses[key]
        return HttpResponse(
            ok=True,
            url=url,
            status_code=404,
            headers={"Content-Type": "text/plain"},
            body=b"not found",
            response_time_ms=5,
            error=None,
        )

    def close(self) -> None:
        return None



def test_probe_api_subpaths_discovers_search_query_candidate() -> None:
    client = FakeProbeClient(
        {
            (
                "/rest/products/search",
                (("q", "probe"),),
            ): HttpResponse(
                ok=True,
                url="http://example.test/rest/products/search",
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=b'{"items":[]}',
                response_time_ms=5,
                error=None,
            )
        }
    )

    result = probe_api_subpaths(
        "http://example.test",
        ["/rest/products"],
        cast(HttpClient, client),
        timeout=1.0,
        max_bytes=50_000,
    )

    assert "/rest/products/search?q=probe" in result



def test_probe_api_subpaths_excludes_fallback_signature_matches() -> None:
    fallback_body = b'{"spa":true}'
    client = FakeProbeClient(
        {
            (
                "/rest/products/search",
                (("q", "probe"),),
            ): HttpResponse(
                ok=True,
                url="http://example.test/rest/products/search",
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=fallback_body,
                response_time_ms=5,
                error=None,
            )
        }
    )

    result = probe_api_subpaths(
        "http://example.test",
        ["/rest/products"],
        cast(HttpClient, client),
        timeout=1.0,
        max_bytes=50_000,
        fallback_sig=body_signature(fallback_body),
    )

    assert result == []



def test_probe_api_subpaths_skips_static_suffix_endpoint() -> None:
    client = FakeProbeClient({})

    result = probe_api_subpaths(
        "http://example.test",
        ["/assets/main.js"],
        cast(HttpClient, client),
        timeout=1.0,
        max_bytes=50_000,
    )

    assert result == []
    assert client.calls == []



def test_probe_api_subpaths_deduplicates_existing_candidate() -> None:
    client = FakeProbeClient(
        {
            (
                "/rest/products/search",
                (("q", "probe"),),
            ): HttpResponse(
                ok=True,
                url="http://example.test/rest/products/search",
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=b'{"items":[]}',
                response_time_ms=5,
                error=None,
            )
        }
    )

    result = probe_api_subpaths(
        "http://example.test",
        ["/rest/products", "/rest/products/search?q=probe"],
        cast(HttpClient, client),
        timeout=1.0,
        max_bytes=50_000,
    )

    assert "/rest/products/search?q=probe" not in result
