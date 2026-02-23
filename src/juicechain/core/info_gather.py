from __future__ import annotations

import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


def normalize_target_base(target: str) -> str:
    """
    Normalize user input into a base URL (scheme + host[:port]).

    Accepts:
      - http://host:port/path
      - https://host:port
      - host:port
      - host
      - 127.0.0.1:3000

    Returns:
      - http(s)://host[:port]
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("target is empty")

    if not target.lower().startswith(("http://", "https://")):
        target = "http://" + target

    parsed = urllib.parse.urlparse(target)
    if not parsed.hostname:
        raise ValueError(f"invalid target: {target}")

    netloc = parsed.netloc  # includes port if present
    scheme = parsed.scheme.lower() or "http"
    return f"{scheme}://{netloc}"


def _headers_to_dict(headers_obj: Any) -> dict[str, str]:
    # urllib response headers behaves like email.message.Message
    out: dict[str, str] = {}
    try:
        for k, v in headers_obj.items():
            out[str(k)] = str(v)
    except Exception:
        pass
    return out


@dataclass
class FetchResult:
    ok: bool
    url: str
    status_code: int | None
    headers: dict[str, str]
    body: bytes
    response_time_ms: int | None
    error: str | None


def fetch_url(url: str, timeout: float = 3.0, max_bytes: int = 256_000) -> FetchResult:
    """
    Fetch a URL via HTTP GET.
    - ok=True means we got an HTTP response (including HTTPError like 404/500).
    - For network/timeout/DNS errors, ok=False.
    """
    start = time.perf_counter()
    try:
        req = urllib.request.Request(
            url=url,
            method="GET",
            headers={
                "User-Agent": "JuiceChain/0.3 (info-gather)",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(max_bytes) if max_bytes > 0 else b""
            elapsed_ms = int(round((time.perf_counter() - start) * 1000))
            return FetchResult(
                ok=True,
                url=url,
                status_code=int(getattr(resp, "status", None)) if getattr(resp, "status", None) is not None else None,
                headers=_headers_to_dict(getattr(resp, "headers", {})),
                body=body,
                response_time_ms=elapsed_ms,
                error=None,
            )

    except urllib.error.HTTPError as e:
        # HTTPError is still a valid HTTP response from server
        try:
            body = e.read(max_bytes) if max_bytes > 0 else b""
        except Exception:
            body = b""
        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        return FetchResult(
            ok=True,
            url=url,
            status_code=int(getattr(e, "code", 0) or 0),
            headers=_headers_to_dict(getattr(e, "headers", {})),
            body=body,
            response_time_ms=elapsed_ms,
            error=None,
        )

    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        return FetchResult(
            ok=False,
            url=url,
            status_code=None,
            headers={},
            body=b"",
            response_time_ms=elapsed_ms,
            error=f"{type(e).__name__}: {e}",
        )


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


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
    title = m.group(1)
    title = re.sub(r"\s+", " ", title).strip()
    return title or None


def fingerprint_from_headers(headers: dict[str, str]) -> dict[str, Any]:
    server = headers.get("Server") or headers.get("server")
    x_powered_by = headers.get("X-Powered-By") or headers.get("x-powered-by")

    hints: list[str] = []
    if server:
        s = server.lower()
        if "nginx" in s:
            hints.append("nginx")
        if "apache" in s:
            hints.append("apache")
        if "caddy" in s:
            hints.append("caddy")
        if "openresty" in s:
            hints.append("openresty")
    if x_powered_by:
        x = x_powered_by.lower()
        if "express" in x:
            hints.append("express")
        if "php" in x:
            hints.append("php")
        if "asp.net" in x:
            hints.append("asp.net")

    # de-dup while preserving order
    seen: set[str] = set()
    dedup = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            dedup.append(h)

    return {
        "server": server,
        "x_powered_by": x_powered_by,
        "hints": dedup,
    }


def parse_robots(robots_text: str) -> dict[str, Any]:
    disallow: list[str] = []
    allow: list[str] = []
    sitemaps: list[str] = []
    user_agents: list[str] = []

    for raw_line in robots_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # strip comments
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

    return {
        "user_agents": user_agents,
        "disallow": disallow,
        "allow": allow,
        "sitemaps": sitemaps,
    }


def gather_info(target: str, timeout: float = 3.0, max_bytes: int = 256_000) -> dict[str, Any]:
    """
    Passive info gather:
      - fetch homepage (base + "/")
      - collect status_code/headers/response_time/title
      - fetch robots.txt (base + "/robots.txt")
    Output is JSON-friendly dict.
    """
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
        },
        "fingerprint": {
            "server": None,
            "x_powered_by": None,
            "hints": [],
        },
        "robots": {
            "url": None,
            "ok": False,
            "status_code": None,
            "response_time_ms": None,
            "directives": {
                "user_agents": [],
                "disallow": [],
                "allow": [],
                "sitemaps": [],
            },
            "error": None,
        },
        "errors": [],
    }

    try:
        base = normalize_target_base(target)
        out["target"] = base
    except Exception as e:
        out["errors"].append(f"{type(e).__name__}: {e}")
        return out

    # 1) Homepage
    home_url = urllib.parse.urljoin(base + "/", "/")
    home = fetch_url(home_url, timeout=timeout, max_bytes=max_bytes)
    out["homepage"]["url"] = home.url
    out["homepage"]["status_code"] = home.status_code
    out["homepage"]["response_time_ms"] = home.response_time_ms
    out["homepage"]["headers"] = home.headers
    out["homepage"]["content_length"] = len(home.body) if home.body is not None else None
    out["homepage"]["title"] = extract_title(home.body)

    if home.ok:
        out["ok"] = True
        out["fingerprint"] = fingerprint_from_headers(home.headers)
    else:
        out["errors"].append(home.error or "homepage fetch failed")

    # 2) robots.txt (independent; even if homepage fails, still try)
    robots_url = urllib.parse.urljoin(base + "/", "/robots.txt")
    rob = fetch_url(robots_url, timeout=timeout, max_bytes=max_bytes)
    out["robots"]["url"] = rob.url
    out["robots"]["status_code"] = rob.status_code
    out["robots"]["response_time_ms"] = rob.response_time_ms

    if rob.ok and rob.status_code and 200 <= rob.status_code < 300:
        try:
            text = rob.body.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        out["robots"]["ok"] = True
        out["robots"]["directives"] = parse_robots(text)
        out["robots"]["error"] = None
    else:
        out["robots"]["ok"] = False
        out["robots"]["error"] = rob.error  # may be None for 404; that's fine

    return out