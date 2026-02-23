from __future__ import annotations

import urllib.parse


def normalize_target_base(target: str) -> str:
    """
    Normalize user input into base URL: http(s)://host[:port]
    """
    t = (target or "").strip()
    if not t:
        raise ValueError("target is empty")

    if not t.lower().startswith(("http://", "https://")):
        t = "http://" + t

    p = urllib.parse.urlparse(t)
    if not p.hostname:
        raise ValueError(f"invalid target: {t}")

    scheme = (p.scheme or "http").lower()
    netloc = p.netloc
    return f"{scheme}://{netloc}"


def join_url(base: str, path: str) -> str:
    return urllib.parse.urljoin(base.rstrip("/") + "/", "/" + path.lstrip("/"))