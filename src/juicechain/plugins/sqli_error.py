from __future__ import annotations

import re
from typing import Any, ClassVar

from juicechain.core.http_client import HttpClient
from juicechain.core.input_point import InputPoint, Location
from juicechain.core.target import join_url
from juicechain.plugins.base import Finding, VulnPlugin
from juicechain.utils.logging import get_logger

logger = get_logger(__name__)

_SQL_ERR_PATTERNS = [
    r"sqlite_error",
    r"sqlite3::SQLException".lower(),
    r"sequelize[\w]*error",
    r"sequelize/lib",
    r"sequelize\.js",
    r"dialects/sqlite",
    r"dialects/mysql",
    r"dialects/postgres",
    r"dialects/mssql",
    r"node_modules/sequelize",
    r"node_modules/knex",
    r"node_modules/typeorm",
    r"node_modules/prisma",
    r"SequelizeDatabaseError",
    r"sqlite3\.(?:Database|Statement)",
    r"SQLITE_(?:ERROR|CONSTRAINT|MISMATCH|RANGE)",
    r"at\s+(?:Query|Database|Statement|Connection)\.",
    r"\.query\.js:\d+",
    r"sql syntax",
    r"syntax error",
    r"unterminated",
    r"unrecognized token",
    r"near \"",
    r"odbc",
    r"mysql",
    r"postgres",
    r"psql",
]
_SQL_ERR_RE = re.compile("|".join(_SQL_ERR_PATTERNS), re.IGNORECASE)


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
    name: ClassVar[str] = "SQLI_ERROR"
    severity: ClassVar[str] = "high"
    supported_locations: ClassVar[set[Location]] = {"query", "body_json", "header"}

    def _json_group(self, point: InputPoint) -> list[InputPoint]:
        all_points = getattr(self, "_all_points", None)
        if not isinstance(all_points, list):
            return [point]
        out: list[InputPoint] = []
        for candidate in all_points:
            if not isinstance(candidate, InputPoint):
                continue
            if (
                candidate.method == point.method
                and candidate.path == point.path
                and candidate.location == "body_json"
            ):
                out.append(candidate)
        return out or [point]

    def check(
        self,
        base: str,
        point: InputPoint,
        client: HttpClient,
        timeout: float,
        max_bytes: int,
    ) -> Finding | None:
        payloads = ["'", "' OR '1'='1'--", '"', '" OR "1"="1"--']

        if point.location == "query" and point.method == "GET":
            url = join_url(base, point.path)
            for payload in payloads[:2]:
                res = client.request("GET", url, timeout=timeout, max_bytes=max_bytes, params={point.param: payload})
                if not res.ok:
                    continue
                text = res.text()
                if _SQL_ERR_RE.search(text):
                    evidence = f"possible SQL error keyword in response: ...{_snippet_around(text.lower(), 'error')}..."
                    logger.info("potential SQLi error-based finding: path=%s param=%s", point.path, point.param)
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
            return None

        if point.location == "body_json" and point.method == "POST":
            url = join_url(base, point.path)
            group = self._json_group(point)

            base_body: dict[str, Any] = {}
            for g in group:
                base_body[g.param] = g.original_value or "test"

            for payload in payloads[:2]:
                body = dict(base_body)
                body[point.param] = payload

                res = client.request(
                    "POST",
                    url,
                    timeout=timeout,
                    max_bytes=max_bytes,
                    headers={"Content-Type": "application/json"},
                    json_data=body,
                )
                if not res.ok:
                    continue
                text = res.text()
                if _SQL_ERR_RE.search(text):
                    evidence = f"possible SQL error keyword in response: ...{_snippet_around(text, 'error')}..."
                    logger.info("potential SQLi error-based finding: path=%s param=%s", point.path, point.param)
                    return Finding(
                        vuln_type=self.name,
                        severity=self.severity,
                        evidence=evidence,
                        request={
                            "method": "POST",
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

        if point.location == "header":
            url = join_url(base, point.path)
            for payload in payloads[:2]:
                headers = dict(point.extra_headers)
                headers[point.param] = payload
                res = client.request(
                    point.method,
                    url,
                    timeout=timeout,
                    max_bytes=max_bytes,
                    headers=headers,
                )
                if not res.ok:
                    continue
                text = res.text()
                if _SQL_ERR_RE.search(text):
                    evidence = f"possible SQL error keyword in response: ...{_snippet_around(text.lower(), 'error')}..."
                    logger.info("potential SQLi error-based finding: path=%s param=%s", point.path, point.param)
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
                            "time_ms": res.response_time_ms,
                        },
                    )
            return None

        return None
