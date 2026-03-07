from __future__ import annotations

import re
import secrets
from typing import ClassVar

from juicechain.core.http_client import HttpClient, HttpResponse
from juicechain.core.input_point import InputPoint, Location
from juicechain.core.target import join_url
from juicechain.plugins.base import Finding, VulnPlugin
from juicechain.utils.logging import get_logger

logger = get_logger(__name__)

_HTML_HINT_RE = re.compile(r"(?is)<\s*(html|head|body)\b")


def _is_html_response(res: HttpResponse) -> bool:
    ct = (res.content_type() or "").lower()
    if "text/html" in ct:
        return True
    return bool(_HTML_HINT_RE.search(res.text()))


def _snippet_around(text: str, needle: str, *, radius: int = 80) -> str:
    if not text or not needle:
        return ""
    idx = text.find(needle)
    if idx < 0:
        return ""
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    return text[start:end].replace("\n", " ").replace("\r", " ").strip()


class Plugin(VulnPlugin):
    name: ClassVar[str] = "XSS_REFLECTED"
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
        if point.location != "query" or point.method != "GET":
            return None

        token = secrets.token_hex(4)
        payload = f"<script>JCXSS_{token}</script>"
        url = join_url(base, point.path)

        res = client.request("GET", url, timeout=timeout, max_bytes=max_bytes, params={point.param: payload})
        if not res.ok:
            return None

        text = res.text()
        if payload not in text:
            return None

        if _is_html_response(res):
            evidence = f"payload reflected in HTML response: ...{_snippet_around(text, payload)}..."
            logger.info("potential reflected XSS found: path=%s param=%s", point.path, point.param)
            return Finding(
                vuln_type=self.name,
                severity=self.severity,
                evidence=evidence,
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

        ct = (res.content_type() or "").lower()
        if "json" in ct:
            evidence = f"payload reflected in JSON response: ...{_snippet_around(text, payload)}..."
            logger.info("potential reflected XSS(JSON) found: path=%s param=%s", point.path, point.param)
            return Finding(
                vuln_type=self.name,
                severity="medium",
                evidence=evidence,
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
