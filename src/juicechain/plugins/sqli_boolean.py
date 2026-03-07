from __future__ import annotations

import json
import secrets
from collections.abc import Mapping
from typing import Any, ClassVar

from juicechain.core.http_client import HttpClient
from juicechain.core.input_point import InputPoint, Location
from juicechain.core.target import join_url
from juicechain.plugins.base import Finding, VulnPlugin
from juicechain.utils.logging import get_logger

logger = get_logger(__name__)

_BOOLEAN_SQLI_SKIP_SUFFIXES: tuple[str, ...] = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".svg",
    ".woff",
    ".map",
)
_BOOLEAN_SQLI_SKIP_EXACT_PATHS: tuple[str, ...] = ("/robots.txt", "/sitemap.xml")


def _try_json(text: str) -> Any | None:
    try:
        return json.loads(text)
    except Exception:
        return None


def _count_items(obj: Any) -> int | None:
    if isinstance(obj, list):
        return len(obj)
    if isinstance(obj, Mapping):
        for value in obj.values():
            if isinstance(value, list):
                return len(value)
    return None


def _normalized_path(path: str) -> str:
    normalized = (path or "").strip().lower().split("?", 1)[0]
    if not normalized:
        return ""
    if normalized != "/":
        normalized = normalized.rstrip("/")
    return normalized


def _is_boolean_sqli_candidate_path(path: str) -> bool:
    normalized = _normalized_path(path)
    if not normalized:
        return False
    if normalized in _BOOLEAN_SQLI_SKIP_EXACT_PATHS:
        return False
    if any(normalized.endswith(suffix) for suffix in _BOOLEAN_SQLI_SKIP_SUFFIXES):
        return False
    return True


def _content_family(content_type: str | None) -> str:
    ct = (content_type or "").lower()
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    return "other"


class Plugin(VulnPlugin):
    name: ClassVar[str] = "SQLI_BOOLEAN"
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
        if not (point.method == "GET" and point.location == "query"):
            return None

        if not _is_boolean_sqli_candidate_path(point.path):
            return None

        url = join_url(base, point.path)

        baseline_token = f"jc_{secrets.token_hex(4)}"
        inj = "' OR 1=1-- "

        r0 = client.request("GET", url, timeout=timeout, max_bytes=max_bytes, params={point.param: baseline_token})
        r1 = client.request("GET", url, timeout=timeout, max_bytes=max_bytes, params={point.param: inj})

        if not (r0.ok and r1.ok):
            return None

        if (r0.status_code is None) or (r1.status_code is None):
            return None
        if r0.status_code >= 400 or r1.status_code >= 400:
            return None

        ct0 = _content_family(r0.content_type())
        ct1 = _content_family(r1.content_type())
        if ct1 != ct0:
            return None
        if ct0 != "json":
            return None

        t0 = r0.text()
        t1 = r1.text()

        j0 = _try_json(t0)
        j1 = _try_json(t1)
        c0 = _count_items(j0) if j0 is not None else None
        c1 = _count_items(j1) if j1 is not None else None

        suspected_by_count = (c0 is not None and c1 is not None and c1 >= max(5, (c0 + 5)))
        suspected_by_len = (len(t1) >= len(t0) + 800 and len(t1) >= len(t0) * 2)
        if not (suspected_by_count or suspected_by_len):
            return None

        r2 = client.request("GET", url, timeout=timeout, max_bytes=max_bytes, params={point.param: baseline_token})
        if not r2.ok:
            return None
        if r2.status_code is None or r2.status_code >= 400:
            return None
        if _content_family(r2.content_type()) != ct0:
            return None

        t2 = r2.text()
        j2 = _try_json(t2)
        c2 = _count_items(j2) if j2 is not None else None

        if suspected_by_count and c2 is not None and c2 == c0:
            evidence = f"item count changed (baseline={c0}, injected={c1})"
            logger.info("potential SQLi boolean finding: path=%s param=%s", point.path, point.param)
            return Finding(
                vuln_type=self.name,
                severity=self.severity,
                evidence=evidence,
                request={
                    "method": "GET",
                    "url": url,
                    "location": point.location,
                    "param": point.param,
                    "payload": inj,
                },
                response={
                    "status_code": r1.status_code,
                    "content_type": r1.content_type(),
                    "time_ms": r1.response_time_ms,
                },
            )

        baseline_len_drift = abs(len(t2) - len(t0))
        allowed_len_drift = max(120, int(len(t0) * 0.15))
        if suspected_by_len and baseline_len_drift <= allowed_len_drift:
            evidence = f"response length changed (baseline={len(t0)}, injected={len(t1)})"
            logger.info("potential SQLi boolean finding(length): path=%s param=%s", point.path, point.param)
            return Finding(
                vuln_type=self.name,
                severity="medium",
                evidence=evidence,
                request={
                    "method": "GET",
                    "url": url,
                    "location": point.location,
                    "param": point.param,
                    "payload": inj,
                },
                response={
                    "status_code": r1.status_code,
                    "content_type": r1.content_type(),
                    "time_ms": r1.response_time_ms,
                },
            )

        return None
