from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def normalize_target(target: str) -> str:
    """
    Normalize user input into a valid URL.

    Accepts:
      - http://host:port
      - https://host:port
      - host:port
      - host
      - 127.0.0.1:3000
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("target is empty")

    # IMPORTANT:
    # "192.168.204.24:3000" will be parsed as scheme by urlparse if we don't prefix scheme.
    if not target.lower().startswith(("http://", "https://")):
        target = "http://" + target

    parsed = urllib.parse.urlparse(target)
    if not parsed.hostname:
        raise ValueError(f"invalid target: {target}")

    return target


def check_http_alive(target: str, timeout: float = 3.0) -> dict[str, Any]:
    """
    Check whether an HTTP service is reachable.

    Alive means:
      - we can get an HTTP response (any status code counts as alive)

    Returns:
      {
        "target": "<normalized_url or original>",
        "alive": true/false,
        "status_code": int or null,
        "response_time_ms": int or null,
        "error": str or null
      }
    """
    result: dict[str, Any] = {
        "target": target,
        "alive": False,
        "status_code": None,
        "response_time_ms": None,
        "error": None,
    }

    try:
        normalized_url = normalize_target(target)
        result["target"] = normalized_url
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result

    start = time.perf_counter()
    try:
        req = urllib.request.Request(
            url=normalized_url,
            method="GET",
            headers={
                "User-Agent": "JuiceChain/0.1 (alive-check)",
                "Accept": "*/*",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = getattr(resp, "status", None)
            result["status_code"] = int(status_code) if status_code is not None else None

        result["response_time_ms"] = int(round((time.perf_counter() - start) * 1000))
        result["alive"] = True
        return result

    except urllib.error.HTTPError as e:
        # HTTPError also means server responded (e.g., 404/500) => alive
        result["response_time_ms"] = int(round((time.perf_counter() - start) * 1000))
        result["status_code"] = int(getattr(e, "code", 0) or 0)
        result["alive"] = True
        result["error"] = None
        return result

    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        result["response_time_ms"] = int(round((time.perf_counter() - start) * 1000))
        result["error"] = f"{type(e).__name__}: {e}"
        result["alive"] = False
        return result
