from __future__ import annotations

import urllib.parse


def normalize_target_base(target: str) -> str:
    """Normalize user input into `http(s)://host[:port]` form.

    Args:
        target: Raw target string from CLI/user input.

    Returns:
        Normalized target base URL including scheme and netloc only.

    Raises:
        ValueError: If target is empty or cannot be parsed to a valid host.
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
    """Join a base URL and relative path with predictable slash behavior.

    Args:
        base: Absolute base URL.
        path: Relative or absolute path.

    Returns:
        Joined absolute URL string.
    """
    return urllib.parse.urljoin(base.rstrip("/") + "/", "/" + path.lstrip("/"))
