from __future__ import annotations

from juicechain.core.http_client import HttpResponse
from juicechain.core.vulnerability import InputPoint, check_auth_bypass


class FakeLoginClient:
    def request(self, method, url, **kwargs):
        json_data = kwargs.get("json_data") or {}
        email = str(json_data.get("email", ""))

        # baseline: benign/non-existent email -> 401
        if "nonexist" in email or "jctest" in email:
            return HttpResponse(
                ok=True,
                url=url,
                status_code=401,
                headers={"Content-Type": "application/json"},
                body=b'{"error":"Invalid email or password."}',
                response_time_ms=5,
                error=None,
            )

        # bypass payload -> 200 + token
        if "OR 1=1" in email or "' OR" in email:
            return HttpResponse(
                ok=True,
                url=url,
                status_code=200,
                headers={"Content-Type": "application/json"},
                body=b'{"authentication":{"token":"eyJhbGciOiJ..."}}',
                response_time_ms=5,
                error=None,
            )

        return HttpResponse(
            ok=True,
            url=url,
            status_code=401,
            headers={"Content-Type": "application/json"},
            body=b'{"error":"Invalid email or password."}',
            response_time_ms=5,
            error=None,
        )

    def close(self):
        return None


def test_check_auth_bypass_returns_finding_for_login_json():
    pts = [
        InputPoint(method="POST", path="/rest/user/login", location="json", param="email"),
        InputPoint(method="POST", path="/rest/user/login", location="json", param="password"),
    ]
    group = {("POST", "/rest/user/login"): pts}

    f = check_auth_bypass(
        base="http://example.test",
        pt=pts[0],
        client=FakeLoginClient(),
        timeout=1.0,
        max_bytes=50_000,
        json_field_group=group,
    )
    assert f is not None
    assert f.type == "AUTH_BYPASS"
    assert f.severity == "critical"


def test_check_auth_bypass_returns_none_for_non_login_path():
    pts = [
        InputPoint(method="POST", path="/rest/user/profile", location="json", param="email"),
        InputPoint(method="POST", path="/rest/user/profile", location="json", param="password"),
    ]
    group = {("POST", "/rest/user/profile"): pts}

    f = check_auth_bypass(
        base="http://example.test",
        pt=pts[0],
        client=FakeLoginClient(),
        timeout=1.0,
        max_bytes=50_000,
        json_field_group=group,
    )
    assert f is None


def test_check_auth_bypass_returns_none_for_non_json_point():
    pt = InputPoint(method="GET", path="/rest/user/login", location="query", param="email")

    f = check_auth_bypass(
        base="http://example.test",
        pt=pt,
        client=FakeLoginClient(),
        timeout=1.0,
        max_bytes=50_000,
        json_field_group={},
    )
    assert f is None
