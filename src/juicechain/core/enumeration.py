from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse, urlunparse, urljoin, parse_qs

from bs4 import BeautifulSoup

from .http_client import HttpClient, body_signature
from .target import normalize_target_base, join_url


_HASH_ROUTE_RE = re.compile(r"(?:/)?#/[A-Za-z0-9_\-\/]+")
_HASH_ROUTE_QUOTED_RE = re.compile(r"""["'](?:/)?#/[A-Za-z0-9_\-\/]+["']""")

# Angular route configs typically contain: path:"login" / redirectTo:"search"
_ANGULAR_ROUTE_PATH_RE = re.compile(r"""(?:\bpath\b|["']path["'])\s*:\s*["']([^"']{0,80})["']""")
_ANGULAR_REDIRECT_RE = re.compile(r"""(?:\bredirectTo\b|["']redirectTo["'])\s*:\s*["']([^"']{0,120})["']""")

# Rough API/path candidates in JS bundles
_API_CANDIDATE_RE = re.compile(
    r"""["']/(?:rest|api|graphql|socket\.io|ws|uploads|assets)[A-Za-z0-9_\-\/\.\?=&%]*["']"""
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _canonicalize_url(url: str) -> str:
    p = urlparse(url)
    p = p._replace(fragment="")
    return urlunparse(p)


def _same_origin(base: str, other: str) -> bool:
    b = urlparse(base)
    o = urlparse(other)
    return (b.scheme, b.netloc) == (o.scheme, o.netloc)


def _extract_query_param_names(url: str) -> list[str]:
    p = urlparse(url)
    qs = parse_qs(p.query)
    return sorted(qs.keys())


def _normalize_link(base: str, href: str) -> tuple[str | None, str | None]:
    if not href:
        return None, None
    href = href.strip()
    low = href.lower()

    if low.startswith(("javascript:", "mailto:", "tel:")):
        return None, None

    if href.startswith("#/") or href.startswith("/#/"):
        return None, href

    abs_url = urljoin(base.rstrip("/") + "/", href)
    return abs_url, None


def _looks_like_html(headers: dict[str, str], body: bytes) -> bool:
    ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    if "text/html" in ct:
        return True
    head = body[:2048].lower()
    return b"<html" in head or b"<!doctype html" in head


def _extract_title_from_bytes(b: bytes) -> str | None:
    if not b:
        return None
    try:
        t = b.decode("utf-8", errors="ignore")
    except Exception:
        return None
    m = _TITLE_RE.search(t)
    if not m:
        return None
    title = re.sub(r"\s+", " ", (m.group(1) or "")).strip()
    return title or None


def _scan_hash_routes_from_text(text: str) -> set[str]:
    out: set[str] = set()
    if not text:
        return out
    for m in _HASH_ROUTE_RE.findall(text):
        out.add(m)
    for m in _HASH_ROUTE_QUOTED_RE.findall(text):
        out.add(m.strip("\"'"))
    return out


def _clean_angular_route_segment(seg: str) -> str | None:
    """
    Normalize an Angular route "path" segment to something we can map.
    Examples:
      "login" -> "login"
      "/login" -> "login"
      "administration" -> "administration"
      "**" / "*" / "" -> None
      "rest/user/login" -> None (avoid API-ish)
    """
    s = (seg or "").strip()
    if not s:
        return None

    # common wildcards / placeholders
    if s in ("*", "**"):
        return None

    # remove leading hash forms
    if s.startswith("/#/"):
        s = s[3:]
    if s.startswith("#/"):
        s = s[2:]

    # drop query/fragment
    if "?" in s:
        s = s.split("?", 1)[0]
    if "#" in s:
        s = s.split("#", 1)[0]

    s = s.strip()
    if not s:
        return None

    # strip leading slash
    if s.startswith("/"):
        s = s[1:]

    s = s.strip("/")

    # filter obviously non-route strings
    if not s:
        return None
    if len(s) > 60:
        return None
    if any(ch.isspace() for ch in s):
        return None
    if any(ch in s for ch in (":", ";", "=", "%", "\\", "{", "}", "<", ">")):
        return None
    if "." in s:  # avoid "main.js" like strings
        return None

    low = s.lower()
    # exclude API-like segments
    if low.startswith(("api/", "rest/", "graphql", "socket.io", "ws/")):
        return None

    return s


def _scan_angular_routes_from_js(text: str) -> tuple[set[str], set[str]]:
    """
    Extract Angular route segments from JS bundles:
    - path:"login"
    - redirectTo:"search"
    Returns:
      (route_paths, normalized_hash_routes)
    """
    route_paths: set[str] = set()
    hash_routes: set[str] = set()

    if not text:
        return route_paths, hash_routes

    # path:
    for m in _ANGULAR_ROUTE_PATH_RE.finditer(text):
        seg = _clean_angular_route_segment(m.group(1))
        if not seg:
            continue
        route_paths.add(seg)
        hash_routes.add(f"#/{seg}")

    # redirectTo:
    for m in _ANGULAR_REDIRECT_RE.finditer(text):
        seg = _clean_angular_route_segment(m.group(1))
        if not seg:
            continue
        route_paths.add(seg)
        hash_routes.add(f"#/{seg}")

    return route_paths, hash_routes


def _scan_api_candidates_from_js(text: str) -> set[str]:
    out: set[str] = set()
    if not text:
        return out
    for m in _API_CANDIDATE_RE.findall(text):
        out.add(m.strip("\"'"))
    return out


def _extract_asset_urls(base: str, html: bytes) -> list[str]:
    if not html:
        return []
    soup = BeautifulSoup(html, "html.parser")
    urls: set[str] = set()

    for s in soup.find_all("script"):
        src = (s.get("src") or "").strip()
        if not src:
            continue
        abs_url = urljoin(base.rstrip("/") + "/", src)
        abs_url = _canonicalize_url(abs_url)
        if _same_origin(base, abs_url):
            urls.add(abs_url)

    for l in soup.find_all("link"):
        href = (l.get("href") or "").strip()
        if not href:
            continue
        rel = (l.get("rel") or [])
        rel_s = " ".join([str(x).lower() for x in rel]) if isinstance(rel, list) else str(rel).lower()
        if any(k in rel_s for k in ("stylesheet", "preload", "modulepreload")):
            abs_url = urljoin(base.rstrip("/") + "/", href)
            abs_url = _canonicalize_url(abs_url)
            if _same_origin(base, abs_url):
                urls.add(abs_url)

    return sorted(urls)


@dataclass
class FallbackSignature:
    url: str
    status_code: int | None
    sig: str
    title: str | None
    content_type: str | None


def detect_spa_fallback(base: str, client: HttpClient, *, timeout: float) -> FallbackSignature | None:
    token = secrets.token_hex(8)
    probe_path = f"/__juicechain_probe__/{token}"
    url = join_url(base, probe_path)

    res = client.request("GET", url, timeout=timeout, max_bytes=120_000)
    if not res.ok:
        return None

    ct = (res.headers.get("Content-Type") or res.headers.get("content-type") or "").strip() or None
    title = _extract_title_from_bytes(res.body)
    sig = body_signature(res.body)
    if not sig:
        return None

    return FallbackSignature(url=url, status_code=res.status_code, sig=sig, title=title, content_type=ct)


def crawl_site(
    base: str,
    *,
    start_path: str = "/",
    timeout: float = 3.0,
    max_pages: int = 30,
    max_bytes: int = 300_000,
    allow_redirects: bool = False,
    verify_tls: bool = True,
    retries: int = 0,
    min_interval_ms: int = 0,
    fetch_spa_assets: bool = True,
    max_spa_assets: int = 6,
    spa_asset_max_bytes: int = 450_000,
) -> dict[str, Any]:
    start_url = urljoin(base.rstrip("/") + "/", start_path.lstrip("/"))

    client = HttpClient(
        timeout=timeout,
        verify_tls=verify_tls,
        allow_redirects=allow_redirects,
        max_bytes=max_bytes,
        retries=retries,
        min_interval_ms=min_interval_ms,
    )

    visited: set[str] = set()
    queue: list[str] = [_canonicalize_url(start_url)]

    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    discovered_urls: set[str] = set()
    discovered_params: set[str] = set()

    hash_routes: set[str] = set()
    spa_asset_urls: set[str] = set()

    routes_from_assets: set[str] = set()
    route_paths_from_assets: set[str] = set()
    api_candidates: set[str] = set()

    errors: list[str] = []

    try:
        while queue and len(visited) < max_pages:
            current = queue.pop(0)
            cur_can = _canonicalize_url(current)
            if cur_can in visited:
                continue
            if not _same_origin(base, current):
                continue

            visited.add(cur_can)

            res = client.request("GET", current, timeout=timeout, max_bytes=max_bytes)
            if not res.ok:
                errors.append(res.error or f"fetch failed: {current}")
                continue

            pages.append(
                {
                    "url": current,
                    "status_code": res.status_code,
                    "response_time_ms": res.response_time_ms,
                    "content_type": (res.headers.get("Content-Type") or res.headers.get("content-type") or None),
                    "content_length": len(res.body) if res.body is not None else None,
                    "title": _extract_title_from_bytes(res.body),
                }
            )

            for pn in _extract_query_param_names(current):
                discovered_params.add(pn)

            # Hash routes from headers and HTML
            for _, hv in (res.headers or {}).items():
                if hv:
                    hash_routes |= _scan_hash_routes_from_text(str(hv))

            try:
                body_text = res.body.decode("utf-8", errors="ignore")
            except Exception:
                body_text = ""
            hash_routes |= _scan_hash_routes_from_text(body_text)

            if not _looks_like_html(res.headers, res.body):
                continue

            soup = BeautifulSoup(res.body, "html.parser")

            for a in soup.find_all("a"):
                href = a.get("href")
                abs_url, route = _normalize_link(base, (href or ""))
                if route:
                    hash_routes.add(route)
                    continue
                if not abs_url:
                    continue
                abs_url = _canonicalize_url(abs_url)
                if _same_origin(base, abs_url):
                    discovered_urls.add(abs_url)
                    for pn in _extract_query_param_names(abs_url):
                        discovered_params.add(pn)
                    if abs_url not in visited and abs_url not in queue and len(visited) + len(queue) < max_pages * 3:
                        queue.append(abs_url)

            for f in soup.find_all("form"):
                action = f.get("action") or ""
                method = (f.get("method") or "GET").upper().strip()
                abs_action, route = _normalize_link(base, action)
                if route:
                    hash_routes.add(route)
                if abs_action:
                    abs_action = _canonicalize_url(abs_action)
                    if _same_origin(base, abs_action):
                        discovered_urls.add(abs_action)

                input_names: set[str] = set()
                for inp in f.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        input_names.add(str(name).strip())

                forms.append({"page_url": current, "action": abs_action or None, "method": method, "inputs": sorted(input_names)})
                for n in input_names:
                    discovered_params.add(n)

            if fetch_spa_assets:
                for u in _extract_asset_urls(base, res.body):
                    spa_asset_urls.add(u)

        # Fetch JS assets and extract routes/api hints
        if fetch_spa_assets and spa_asset_urls:
            js_assets = [u for u in sorted(spa_asset_urls) if u.lower().endswith((".js", ".mjs"))]
            js_assets = js_assets[: max(0, int(max_spa_assets))]

            for u in js_assets:
                ares = client.request("GET", u, timeout=timeout, max_bytes=int(spa_asset_max_bytes))
                if not ares.ok:
                    continue
                try:
                    js_text = ares.body.decode("utf-8", errors="ignore")
                except Exception:
                    js_text = ""

                # literal "#/..."
                routes_from_assets |= _scan_hash_routes_from_text(js_text)

                # angular "path:" / "redirectTo:"
                rpaths, hroutes = _scan_angular_routes_from_js(js_text)
                route_paths_from_assets |= rpaths
                routes_from_assets |= hroutes

                # API candidates
                api_candidates |= _scan_api_candidates_from_js(js_text)

        # Normalize route strings to "#/xxx"
        def _norm_route(r: str) -> str:
            rr = (r or "").strip()
            if rr.startswith("/#/"):
                rr = rr[1:]
            if rr.startswith("#//"):
                rr = "#/" + rr[3:]
            return rr

        hash_routes = set(_norm_route(r) for r in hash_routes if (r or "").strip())
        routes_from_assets = set(_norm_route(r) for r in routes_from_assets if (r or "").strip())

        return {
            "base": base,
            "start_url": start_url,
            "pages_fetched": pages,
            "urls_discovered": sorted(discovered_urls),
            "forms": forms,
            "param_names": sorted(discovered_params),
            "hash_routes": sorted(hash_routes),
            "spa": {
                "asset_urls": sorted(spa_asset_urls),
                "routes_from_assets": sorted(routes_from_assets),
                "route_paths_from_assets": sorted(route_paths_from_assets),
                "api_candidates_from_assets": sorted(api_candidates),
            },
            "errors": errors,
        }
    finally:
        client.close()


def _route_key(route: str) -> str:
    r = (route or "").strip()
    if r.startswith("/#/"):
        r = r[1:]
    if r.startswith("#/"):
        r = r[2:]
    return r.strip("/").lower()


def _path_key(path: str) -> str:
    p = (path or "").strip().lower()
    return p.strip("/")


def dir_bruteforce(
    base: str,
    paths: Iterable[str],
    *,
    timeout: float = 3.0,
    allow_redirects: bool = False,
    verify_tls: bool = True,
    retries: int = 0,
    min_interval_ms: int = 0,
    detect_fallback: bool = True,
    spa_routes: list[str] | None = None,
) -> dict[str, Any]:
    interesting = {200, 204, 301, 302, 307, 308, 401, 403}

    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    route_keys: set[str] = set()
    if spa_routes:
        for r in spa_routes:
            k = _route_key(r)
            if k:
                route_keys.add(k)

    path_list = [p for p in paths if p]

    client = HttpClient(
        timeout=timeout,
        verify_tls=verify_tls,
        allow_redirects=allow_redirects,
        max_bytes=120_000,
        retries=retries,
        min_interval_ms=min_interval_ms,
    )

    fallback_sig: FallbackSignature | None = None
    try:
        if detect_fallback:
            fallback_sig = detect_spa_fallback(base, client, timeout=timeout)

        for raw in path_list:
            p = raw.strip()
            if not p:
                continue
            if not p.startswith("/"):
                p = "/" + p
            url = join_url(base, p)

            res = client.request("GET", url, timeout=timeout, max_bytes=120_000)
            if not res.ok:
                errors.append(res.error or f"fetch failed: {url}")
                continue

            if res.status_code not in interesting:
                continue

            title = _extract_title_from_bytes(res.body)
            sig = body_signature(res.body)

            suspected_fallback = False
            suspect_reason: str | None = None

            if fallback_sig and res.status_code == fallback_sig.status_code and sig and sig == fallback_sig.sig:
                suspected_fallback = True
                suspect_reason = "body matches non-existent-path fallback probe (likely SPA catch-all)"

            kind = "server_endpoint"
            if suspected_fallback:
                pk = _path_key(p)
                if pk and pk in route_keys:
                    kind = "spa_route"
                else:
                    kind = "fallback_noise"

            findings.append(
                {
                    "path": p,
                    "url": url,
                    "status_code": res.status_code,
                    "response_time_ms": res.response_time_ms,
                    "content_type": (res.headers.get("Content-Type") or res.headers.get("content-type") or None),
                    "title": title,
                    "suspected_fallback": suspected_fallback,
                    "suspect_reason": suspect_reason,
                    "kind": kind,
                }
            )

        confirmed = [f for f in findings if f.get("kind") == "server_endpoint"]
        spa_mapped = [f for f in findings if f.get("kind") == "spa_route"]
        noise = [f for f in findings if f.get("kind") == "fallback_noise"]

        return {
            "base": base,
            "tested": len(path_list),
            "fallback_probe": None
            if not fallback_sig
            else {
                "url": fallback_sig.url,
                "status_code": fallback_sig.status_code,
                "title": fallback_sig.title,
                "content_type": fallback_sig.content_type,
                "signature": fallback_sig.sig,
            },
            "findings_server_endpoints": confirmed,
            "findings_spa_routes": spa_mapped,
            "findings_fallback_noise": noise,
            "errors": errors,
        }
    finally:
        client.close()


def default_wordlist() -> list[str]:
    return [
        "/robots.txt",
        "/sitemap.xml",
        "/security.txt",
        "/.well-known/security.txt",
        "/admin",
        "/login",
        "/register",
        "/api",
        "/swagger",
        "/openapi.json",
        "/graphql",
        "/backup",
        "/.git/",
        "/.env",
    ]


def load_wordlist(path: str) -> list[str]:
    out: list[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
    return out


def enumerate_attack_surface(
    target: str,
    *,
    timeout: float = 3.0,
    max_pages: int = 30,
    max_bytes: int = 300_000,
    paths: list[str] | None = None,
    wordlist_file: str | None = None,
    allow_redirects: bool = False,
    verify_tls: bool = True,
    retries: int = 0,
    min_interval_ms: int = 0,
    fetch_spa_assets: bool = True,
    max_spa_assets: int = 6,
    spa_asset_max_bytes: int = 450_000,
) -> dict[str, Any]:
    out: dict[str, Any] = {"target": target, "ok": False, "crawler": None, "content_discovery": None, "errors": []}

    try:
        base = normalize_target_base(target)
        out["target"] = base
    except Exception as e:
        out["errors"].append(f"{type(e).__name__}: {e}")
        return out

    crawler = crawl_site(
        base,
        timeout=timeout,
        max_pages=max_pages,
        max_bytes=max_bytes,
        allow_redirects=allow_redirects,
        verify_tls=verify_tls,
        retries=retries,
        min_interval_ms=min_interval_ms,
        fetch_spa_assets=fetch_spa_assets,
        max_spa_assets=max_spa_assets,
        spa_asset_max_bytes=spa_asset_max_bytes,
    )
    out["crawler"] = crawler

    if wordlist_file:
        wl = load_wordlist(wordlist_file)
    else:
        wl = paths if paths is not None else default_wordlist()

    # Merge SPA routes from:
    # - routes extracted from assets
    # - hash routes hinted by headers/html (e.g., X-Recruiting: /#/jobs)
    spa_routes: list[str] = []
    try:
        spa_routes.extend(((crawler.get("spa", {}) or {}).get("routes_from_assets", []) or []))
        spa_routes.extend((crawler.get("hash_routes", []) or []))
    except Exception:
        spa_routes = []

    content = dir_bruteforce(
        base,
        wl,
        timeout=timeout,
        allow_redirects=allow_redirects,
        verify_tls=verify_tls,
        retries=retries,
        min_interval_ms=min_interval_ms,
        detect_fallback=True,
        spa_routes=spa_routes,
    )
    out["content_discovery"] = content

    out["ok"] = bool(crawler.get("pages_fetched")) or bool(content.get("findings_server_endpoints")) or bool(
        content.get("findings_spa_routes")
    )

    out["errors"].extend(crawler.get("errors", []))
    out["errors"].extend(content.get("errors", []))
    return out