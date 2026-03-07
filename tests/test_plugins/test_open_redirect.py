from __future__ import annotations

from juicechain.core.http_client import HttpResponse
from juicechain.core.input_point import InputPoint
from juicechain.plugins.open_redirect import Plugin


class RedirectingClient:
    def request(self, method, url, **kwargs):
        del method, url
        params = kwargs.get("params") or {}
        value = str(params.get("redirect", ""))

        location = "https://evil.juicechain.test/path" if "evil.juicechain.test" in value else "https://example.test/home"
        return HttpResponse(
            ok=True,
            url="http://example.test/redirect",
            status_code=302,
            headers={"Location": location, "Content-Type": "text/plain"},
            body=b"",
            response_time_ms=5,
            error=None,
        )


class SameOriginClient:
    def request(self, method, url, **kwargs):
        del method, url, kwargs
        return HttpResponse(
            ok=True,
            url="http://example.test/redirect",
            status_code=302,
            headers={"Location": "https://example.test/profile", "Content-Type": "text/plain"},
            body=b"",
            response_time_ms=5,
            error=None,
        )


def test_open_redirect_finds_external_location_header():
    plugin = Plugin()
    point = InputPoint(method="GET", path="/redirect", location="query", param="redirect")
    finding = plugin.check(
        base="http://example.test",
        point=point,
        client=RedirectingClient(),
        timeout=1.0,
        max_bytes=50_000,
    )

    assert finding is not None
    assert finding.vuln_type == "OPEN_REDIRECT"


def test_open_redirect_ignores_same_origin_redirects():
    plugin = Plugin()
    point = InputPoint(method="GET", path="/redirect", location="query", param="redirect")
    finding = plugin.check(
        base="http://example.test",
        point=point,
        client=SameOriginClient(),
        timeout=1.0,
        max_bytes=50_000,
    )

    assert finding is None
