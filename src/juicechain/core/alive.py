from __future__ import annotations

import time
from typing import Any

from .http_client import HttpClient
from .target import normalize_target_base


def check_http_alive(
    target: str,
    *,
    timeout: float = 3.0,
    verify_tls: bool = True,
    allow_redirects: bool = False,
    retries: int = 0,
) -> dict[str, Any]:
    """
    Alive means: we can get an HTTP response (any status code counts as alive).
    """
    out: dict[str, Any] = {
        "target": target,
        "ok": False,
        "alive": False,
        "status_code": None,
        "response_time_ms": None,
        "error": None,
    }

    try:
        base = normalize_target_base(target)
        out["target"] = base
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
        return out

    client = HttpClient(
        timeout=timeout,
        verify_tls=verify_tls,
        allow_redirects=allow_redirects,
        max_bytes=0,
        retries=retries,
    )
    start = time.perf_counter()
    try:
        res = client.request("HEAD", base, max_bytes=0)
        if res.ok and res.status_code in (405, 501):
            res = client.request("GET", base, max_bytes=0)

        out["response_time_ms"] = int(round((time.perf_counter() - start) * 1000))
        out["status_code"] = res.status_code
        out["ok"] = bool(res.ok)
        out["alive"] = bool(res.ok)
        out["error"] = res.error
        return out
    finally:
        client.close()