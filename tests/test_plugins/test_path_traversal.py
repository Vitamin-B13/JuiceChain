from __future__ import annotations

from juicechain.core.http_client import HttpResponse
from juicechain.core.input_point import InputPoint
from juicechain.plugins.path_traversal import Plugin


class TraversalClient:
    def request(self, method, url, **kwargs):
        del method, url
        payload = str((kwargs.get("params") or {}).get("file", ""))
        if ".." in payload:
            body = b"root:x:0:0:root:/root:/bin/bash"
        else:
            body = b"ok"
        return HttpResponse(
            ok=True,
            url="http://example.test/download",
            status_code=200,
            headers={"Content-Type": "text/plain"},
            body=body,
            response_time_ms=5,
            error=None,
        )


class NoCallClient:
    def request(self, method, url, **kwargs):
        del method, url, kwargs
        raise AssertionError("request should not run for skipped parameters")


def test_path_traversal_finds_passwd_pattern():
    plugin = Plugin()
    point = InputPoint(method="GET", path="/download", location="query", param="file")
    finding = plugin.check(
        base="http://example.test",
        point=point,
        client=TraversalClient(),
        timeout=1.0,
        max_bytes=50_000,
    )

    assert finding is not None
    assert finding.vuln_type == "PATH_TRAVERSAL"


def test_path_traversal_skips_non_file_like_param_names():
    plugin = Plugin()
    point = InputPoint(method="GET", path="/download", location="query", param="email")
    finding = plugin.check(
        base="http://example.test",
        point=point,
        client=NoCallClient(),
        timeout=1.0,
        max_bytes=50_000,
    )

    assert finding is None
