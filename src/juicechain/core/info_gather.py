from __future__ import annotations

import re
from typing import Any

from juicechain.utils.logging import get_logger

from .http_client import HttpClient
from .target import normalize_target_base, join_url

logger = get_logger(__name__)


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_HASH_ROUTE_RE = re.compile(r"(?:/)?#/[A-Za-z0-9_\-\/]+")


def extract_title(html_bytes: bytes) -> str | None:
    if not html_bytes:
        return None
    try:
        text = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return None
    m = _TITLE_RE.search(text)
    if not m:
        return None
    title = re.sub(r"\s+", " ", (m.group(1) or "")).strip()
    return title or None


def fingerprint_from_headers(headers: dict[str, str]) -> dict[str, Any]:
    def _get(name: str) -> str | None:
        return headers.get(name) or headers.get(name.lower())

    server = _get("Server")
    x_powered_by = _get("X-Powered-By")

    hints: list[str] = []
    if server:
        s = server.lower()
        for k in ("nginx", "apache", "caddy", "openresty", "iis"):
            if k in s:
                hints.append(k)
    if x_powered_by:
        x = x_powered_by.lower()
        for k in ("express", "php", "asp.net", "django", "flask", "laravel", "spring"):
            if k in x:
                hints.append(k)

    seen: set[str] = set()
    dedup: list[str] = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            dedup.append(h)

    return {"server": server, "x_powered_by": x_powered_by, "hints": dedup}


_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

_DEPRECATED_HEADERS = [
    "Feature-Policy",
]


def security_headers_audit(headers: dict[str, str]) -> dict[str, Any]:
    present: dict[str, str] = {}
    missing: list[str] = []
    deprecated_present: dict[str, str] = {}

    lower_map = {k.lower(): v for k, v in headers.items()}

    for h in _SECURITY_HEADERS:
        v = lower_map.get(h.lower())
        if v is None:
            missing.append(h)
        else:
            present[h] = v

    for h in _DEPRECATED_HEADERS:
        v = lower_map.get(h.lower())
        if v is not None:
            deprecated_present[h] = v

    return {"present": present, "missing": missing, "deprecated_present": deprecated_present}


def parse_robots(robots_text: str) -> dict[str, Any]:
    disallow: list[str] = []
    allow: list[str] = []
    sitemaps: list[str] = []
    user_agents: list[str] = []

    for raw_line in robots_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue

        key, val = line.split(":", 1)
        key = key.strip().lower()
        val = val.strip()

        if key == "user-agent":
            user_agents.append(val)
        elif key == "disallow":
            disallow.append(val)
        elif key == "allow":
            allow.append(val)
        elif key == "sitemap":
            sitemaps.append(val)

    return {"user_agents": user_agents, "disallow": disallow, "allow": allow, "sitemaps": sitemaps}


def _spa_hints_from_headers(headers: dict[str, str]) -> dict[str, Any]:
    hints: list[dict[str, str]] = []
    for k, v in (headers or {}).items():
        if not v:
            continue
        m = _HASH_ROUTE_RE.search(str(v))
        if m:
            hints.append({"header": k, "value": str(v), "hash_route": m.group(0)})
    return {"hash_route_hints": hints}


def _spa_hints_from_body(body: bytes) -> dict[str, Any]:
    if not body:
        return {"hash_routes_in_html": []}
    try:
        t = body.decode("utf-8", errors="ignore")
    except Exception:
        return {"hash_routes_in_html": []}
    routes = sorted(set(_HASH_ROUTE_RE.findall(t)))
    return {"hash_routes_in_html": routes}


def gather_info(
    target: str,
    *,
    timeout: float = 3.0,
    verify_tls: bool = True,
    allow_redirects: bool = False,
    max_bytes: int = 256_000,
    retries: int = 0,
) -> dict[str, Any]:
    logger.info("info gather start: target=%s", target)
    out: dict[str, Any] = {
        "target": target,
        "ok": False,
        "homepage": {
            "url": None,
            "status_code": None,
            "response_time_ms": None,
            "headers": {},
            "title": None,
            "content_length": None,
            "content_type": None,
        },
        "fingerprint": {"server": None, "x_powered_by": None, "hints": []},
        "security_headers": {"present": {}, "missing": [], "deprecated_present": {}},
        "spa_hints": {"hash_route_hints": [], "hash_routes_in_html": []},
        "robots": {
            "url": None,
            "ok": False,
            "status_code": None,
            "response_time_ms": None,
            "directives": {"user_agents": [], "disallow": [], "allow": [], "sitemaps": []},
            "error": None,
        },
        "errors": [],
    }

    try:
        base = normalize_target_base(target)
        out["target"] = base
    except Exception as e:
        out["errors"].append(f"{type(e).__name__}: {e}")
        logger.warning("info gather target normalize failed: %s", out["errors"][-1])
        return out

    client = HttpClient(
        timeout=timeout,
        verify_tls=verify_tls,
        allow_redirects=allow_redirects,
        max_bytes=max_bytes,
        retries=retries,
    )
    try:
        home_url = join_url(base, "/")
        home = client.request("GET", home_url, max_bytes=max_bytes)
        out["homepage"]["url"] = home_url
        out["homepage"]["status_code"] = home.status_code
        out["homepage"]["response_time_ms"] = home.response_time_ms
        out["homepage"]["headers"] = home.headers
        out["homepage"]["content_length"] = len(home.body) if home.body is not None else None
        out["homepage"]["content_type"] = home.content_type() or None
        out["homepage"]["title"] = extract_title(home.body)

        if home.ok:
            out["ok"] = True
            out["fingerprint"] = fingerprint_from_headers(home.headers)
            out["security_headers"] = security_headers_audit(home.headers)
            out["spa_hints"] = {}
            out["spa_hints"].update(_spa_hints_from_headers(home.headers))
            out["spa_hints"].update(_spa_hints_from_body(home.body))
        else:
            out["errors"].append(home.error or "homepage fetch failed")
            logger.warning("info gather homepage fetch failed: %s", out["errors"][-1])

        robots_url = join_url(base, "/robots.txt")
        rob = client.request("GET", robots_url, max_bytes=max_bytes)
        out["robots"]["url"] = robots_url
        out["robots"]["status_code"] = rob.status_code
        out["robots"]["response_time_ms"] = rob.response_time_ms

        if rob.ok and rob.status_code and 200 <= rob.status_code < 300:
            out["robots"]["ok"] = True
            out["robots"]["directives"] = parse_robots(rob.text())
            out["robots"]["error"] = None
        else:
            out["robots"]["ok"] = False
            out["robots"]["error"] = rob.error
            if rob.error:
                logger.debug("info gather robots fetch warning: %s", rob.error)

        logger.info(
            "info gather done: target=%s ok=%s homepage_status=%s robots_status=%s",
            out["target"],
            out["ok"],
            out["homepage"]["status_code"],
            out["robots"]["status_code"],
        )
        return out
    finally:
        client.close()
