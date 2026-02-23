from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

import requests
from bs4 import BeautifulSoup

from juicechain.core.info_gather import normalize_target_base


_HASH_ROUTE_RE = re.compile(r"/#/[A-Za-z0-9_\-\/]+")
_WS_RE = re.compile(r"\s+")


def _canonicalize_url(url: str) -> str:
    """
    Canonicalize URL for de-dup in crawling:
    - drop fragment
    - keep query (but you may want to drop it later if it explodes)
    """
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
    """
    Returns (absolute_url, hash_route)
    - absolute_url: fetchable same-origin URL (fragment removed later)
    - hash_route: "/#/xxx" if detected
    """
    if not href:
        return None, None
    href = href.strip()

    # skip non-http links
    low = href.lower()
    if low.startswith(("javascript:", "mailto:", "tel:")):
        return None, None

    # fragment-only or hash routes
    if href.startswith("#/"):
        return None, "/#/" + href[2:].lstrip("/")
    if href.startswith("/#/"):
        return None, href

    abs_url = urljoin(base + "/", href)
    return abs_url, None


@dataclass
class HttpFetch:
    ok: bool
    url: str
    status_code: int | None
    headers: dict[str, str]
    body: str
    response_time_ms: int | None
    error: str | None


def fetch_text(url: str, timeout: float = 3.0, max_bytes: int = 300_000) -> HttpFetch:
    start = time.perf_counter()
    try:
        r = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "JuiceChain/0.4 (enum)"},
        )
        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        # try best-effort decode
        text = r.text
        if max_bytes and len(text) > max_bytes:
            text = text[:max_bytes]
        return HttpFetch(
            ok=True,
            url=url,
            status_code=r.status_code,
            headers={k: v for k, v in r.headers.items()},
            body=text,
            response_time_ms=elapsed_ms,
            error=None,
        )
    except requests.RequestException as e:
        elapsed_ms = int(round((time.perf_counter() - start) * 1000))
        return HttpFetch(
            ok=False,
            url=url,
            status_code=None,
            headers={},
            body="",
            response_time_ms=elapsed_ms,
            error=f"{type(e).__name__}: {e}",
        )


def crawl_site(
    base: str,
    start_path: str = "/",
    timeout: float = 3.0,
    max_pages: int = 30,
    max_bytes: int = 300_000,
) -> dict[str, Any]:
    """
    Crawl fetchable same-origin URLs (HTML only heuristically), extract:
    - pages fetched
    - internal links
    - forms and input names
    - query param names in discovered URLs
    - hash routes (/#/...) found in href or via regex scanning

    Note: For SPA, hash routes won't be fetchable; we still record them.
    """
    start_url = urljoin(base + "/", start_path.lstrip("/"))

    visited: set[str] = set()
    queue: list[str] = [_canonicalize_url(start_url)]
    pages: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    discovered_urls: set[str] = set()
    discovered_params: set[str] = set()
    hash_routes: set[str] = set()
    errors: list[str] = []

    while queue and len(visited) < max_pages:
        current = queue.pop(0)
        cur_can = _canonicalize_url(current)
        if cur_can in visited:
            continue
        if not _same_origin(base, current):
            continue

        visited.add(cur_can)

        res = fetch_text(current, timeout=timeout, max_bytes=max_bytes)
        if not res.ok:
            errors.append(res.error or f"fetch failed: {current}")
            continue

        pages.append(
            {
                "url": current,
                "status_code": res.status_code,
                "response_time_ms": res.response_time_ms,
            }
        )

        # collect params from URL
        for pn in _extract_query_param_names(current):
            discovered_params.add(pn)

        # hash route extraction from body (SPA clue)
        for m in _HASH_ROUTE_RE.findall(res.body):
            hash_routes.add(m)

        # parse HTML for links/forms
        soup = BeautifulSoup(res.body, "html.parser")

        # links
        for a in soup.find_all("a"):
            href = a.get("href")
            abs_url, route = _normalize_link(base, href or "")
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

        # forms
        for f in soup.find_all("form"):
            action = f.get("action") or ""
            method = (f.get("method") or "GET").upper().strip()
            abs_action, route = _normalize_link(base, action)
            if route:
                # form action using hash route is possible in SPA; record as route
                hash_routes.add(route)
            if abs_action:
                abs_action = _canonicalize_url(abs_action)
                if _same_origin(base, abs_action):
                    discovered_urls.add(abs_action)

            input_names: set[str] = set()
            for inp in f.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    input_names.add(_WS_RE.sub(" ", str(name)).strip())

            forms.append(
                {
                    "page_url": current,
                    "action": abs_action or None,
                    "method": method,
                    "inputs": sorted(input_names),
                }
            )
            for n in input_names:
                discovered_params.add(n)

    return {
        "base": base,
        "start_url": start_url,
        "pages_fetched": pages,
        "urls_discovered": sorted(discovered_urls),
        "forms": forms,
        "param_names": sorted(discovered_params),
        "hash_routes": sorted(hash_routes),
        "errors": errors,
    }


def dir_bruteforce(
    base: str,
    paths: Iterable[str],
    timeout: float = 3.0,
) -> dict[str, Any]:
    """
    Try a small list of paths. Record interesting statuses.
    """
    interesting = {200, 204, 301, 302, 307, 308, 401, 403}
    findings: list[dict[str, Any]] = []
    errors: list[str] = []

    for p in paths:
        if not p:
            continue
        p = p.strip()
        if not p.startswith("/"):
            p = "/" + p
        url = urljoin(base + "/", p.lstrip("/"))

        res = fetch_text(url, timeout=timeout, max_bytes=10_000)
        if not res.ok:
            errors.append(res.error or f"fetch failed: {url}")
            continue

        if res.status_code in interesting:
            findings.append(
                {
                    "path": p,
                    "url": url,
                    "status_code": res.status_code,
                    "response_time_ms": res.response_time_ms,
                }
            )

    return {
        "base": base,
        "tested": len(list(paths)) if not isinstance(paths, list) else len(paths),
        "findings": findings,
        "errors": errors,
    }


def default_wordlist() -> list[str]:
    # 保守的小字典：不做大规模爆破，避免噪音与风险
    return [
        "/robots.txt",
        "/sitemap.xml",
        "/security.txt",
        "/.well-known/security.txt",
        "/admin",
        "/backup",
        "/.git/",
        "/.env",
        "/ftp",
        "/ftp/acquisitions.md",
        "/score-board",
    ]


def enumerate_attack_surface(
    target: str,
    timeout: float = 3.0,
    max_pages: int = 30,
    max_bytes: int = 300_000,
    paths: list[str] | None = None,
) -> dict[str, Any]:
    """
    Top-level API for CLI.
    """
    out: dict[str, Any] = {
        "target": target,
        "ok": False,
        "crawler": None,
        "content_discovery": None,
        "errors": [],
    }

    try:
        base = normalize_target_base(target)
        out["target"] = base
    except Exception as e:
        out["errors"].append(f"{type(e).__name__}: {e}")
        return out

    crawler = crawl_site(base, timeout=timeout, max_pages=max_pages, max_bytes=max_bytes)
    out["crawler"] = crawler

    wl = paths if paths is not None else default_wordlist()
    content = dir_bruteforce(base, wl, timeout=timeout)
    out["content_discovery"] = content

    # ok 判定：只要爬虫抓到至少 1 页或字典发现有结果
    out["ok"] = bool(crawler.get("pages_fetched")) or bool(content.get("findings"))
    out["errors"].extend(crawler.get("errors", []))
    out["errors"].extend(content.get("errors", []))

    return out