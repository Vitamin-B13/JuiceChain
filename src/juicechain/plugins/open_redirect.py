from __future__ import annotations

from typing import Any, ClassVar

from juicechain.core.http_client import HttpClient
from juicechain.core.input_point import InputPoint, Location
from juicechain.core.target import join_url
from juicechain.plugins.base import Finding, VulnPlugin
from juicechain.utils.logging import get_logger

logger = get_logger(__name__)

_INJECTED_VALUE = "https://evil.juicechain.test"
_REDIRECT_PARAM_NAMES = {
    "redirect",
    "redirect_uri",
    "next",
    "url",
    "return",
    "returnto",
    "goto",
    "target",
    "dest",
    "destination",
    "redir",
}


class Plugin(VulnPlugin):
    name: ClassVar[str] = "OPEN_REDIRECT"
    severity: ClassVar[str] = "medium"
    supported_locations: ClassVar[set[Location]] = {"query", "body_form", "body_json", "header"}

    def _location_header(self, headers: dict[str, str]) -> str:
        for key, value in headers.items():
            if key.lower() == "location":
                return value
        return ""

    def check(
        self,
        base: str,
        point: InputPoint,
        client: HttpClient,
        timeout: float,
        max_bytes: int,
    ) -> Finding | None:
        if (point.param or "").strip().lower() not in _REDIRECT_PARAM_NAMES:
            return None

        url = join_url(base, point.path)
        headers = dict(point.extra_headers)

        if point.location == "query":
            res = client.request(
                point.method,
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                params={point.param: _INJECTED_VALUE},
                headers=headers,
            )
        elif point.location == "body_json":
            json_body: dict[str, Any] = {point.param: _INJECTED_VALUE}
            headers = {"Content-Type": "application/json", **headers}
            res = client.request(
                point.method,
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                headers=headers,
                json_data=json_body,
            )
        elif point.location == "body_form":
            data: dict[str, Any] = {point.param: _INJECTED_VALUE}
            headers = {"Content-Type": "application/x-www-form-urlencoded", **headers}
            res = client.request(
                point.method,
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                headers=headers,
                data=data,
            )
        elif point.location == "header":
            headers[point.param] = _INJECTED_VALUE
            res = client.request(
                point.method,
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                headers=headers,
            )
        else:
            return None

        if not res.ok:
            return None

        location = self._location_header(res.headers)
        if (
            res.status_code is not None
            and 300 <= res.status_code < 400
            and _INJECTED_VALUE in location
        ):
            logger.info("potential open redirect finding: path=%s param=%s", point.path, point.param)
            return Finding(
                vuln_type=self.name,
                severity=self.severity,
                evidence=f"3xx redirect points to injected external URL: {location}",
                request={
                    "method": point.method,
                    "url": url,
                    "location": point.location,
                    "param": point.param,
                    "payload": _INJECTED_VALUE,
                },
                response={
                    "status_code": res.status_code,
                    "content_type": res.content_type(),
                    "time_ms": res.response_time_ms,
                    "location": location,
                },
            )

        text = res.text()
        text_l = text.lower()
        if (
            res.status_code == 200
            and _INJECTED_VALUE in text
            and "<meta" in text_l
            and "refresh" in text_l
        ):
            logger.info("potential open redirect(meta refresh) finding: path=%s param=%s", point.path, point.param)
            return Finding(
                vuln_type=self.name,
                severity=self.severity,
                evidence="meta refresh points to injected external URL",
                request={
                    "method": point.method,
                    "url": url,
                    "location": point.location,
                    "param": point.param,
                    "payload": _INJECTED_VALUE,
                },
                response={
                    "status_code": res.status_code,
                    "content_type": res.content_type(),
                    "time_ms": res.response_time_ms,
                    "location": location,
                },
            )

        return None
