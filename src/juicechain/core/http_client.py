from __future__ import annotations

import time
import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

import requests


_DEFAULT_UA = "JuiceChain/0.5 (+https://github.com/Vitamin-B13/JuiceChain)"


@dataclass
class HttpResponse:
    ok: bool
    url: str
    status_code: int | None
    headers: dict[str, str]
    body: bytes
    response_time_ms: int | None
    error: str | None

    def text(self) -> str:
        if not self.body:
            return ""
        try:
            return self.body.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def content_type(self) -> str:
        return (self.headers.get("Content-Type") or self.headers.get("content-type") or "").strip()


def _headers_to_dict(h: Mapping[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not h:
        return out
    for k, v in h.items():
        try:
            out[str(k)] = str(v)
        except Exception:
            continue
    return out


class HttpClient:
    """
    Consistent HTTP layer for all modules:
    - streamed read with max_bytes
    - optional retries/backoff
    - optional rate limiting (min_interval_ms)
    """

    def __init__(
        self,
        timeout: float = 3.0,
        verify_tls: bool = True,
        allow_redirects: bool = False,
        max_bytes: int = 300_000,
        headers: Mapping[str, str] | None = None,
        proxy: str | None = None,
        retries: int = 0,
        backoff: float = 0.2,
        min_interval_ms: int = 0,
    ) -> None:
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.allow_redirects = allow_redirects
        self.max_bytes = max_bytes
        self.retries = max(0, int(retries))
        self.backoff = float(backoff)
        self.min_interval_ms = max(0, int(min_interval_ms))

        self._session = requests.Session()
        base_headers = {"User-Agent": _DEFAULT_UA, "Accept": "*/*"}
        if headers:
            base_headers.update(dict(headers))
        self._headers = base_headers

        self._proxies: dict[str, str] | None = None
        if proxy:
            self._proxies = {"http": proxy, "https": proxy}

        self._last_request_ts: float | None = None

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass

    def _throttle(self) -> None:
        if self.min_interval_ms <= 0:
            return
        now = time.perf_counter()
        if self._last_request_ts is None:
            self._last_request_ts = now
            return
        elapsed_ms = (now - self._last_request_ts) * 1000.0
        wait_ms = self.min_interval_ms - elapsed_ms
        if wait_ms > 0:
            time.sleep(wait_ms / 1000.0)
        self._last_request_ts = time.perf_counter()

    def request(
        self,
        method: str,
        url: str,
        *,
        timeout: float | None = None,
        max_bytes: int | None = None,
        allow_redirects: bool | None = None,
        verify_tls: bool | None = None,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        data: Any | None = None,
        json_data: Any | None = None,
    ) -> HttpResponse:
        method = (method or "GET").upper().strip()
        timeout = float(timeout if timeout is not None else self.timeout)
        max_bytes = int(max_bytes if max_bytes is not None else self.max_bytes)
        allow_redirects = bool(self.allow_redirects if allow_redirects is None else allow_redirects)
        verify_tls = bool(self.verify_tls if verify_tls is None else verify_tls)

        merged_headers = dict(self._headers)
        if headers:
            merged_headers.update(dict(headers))

        last_err: str | None = None
        for attempt in range(self.retries + 1):
            self._throttle()
            start = time.perf_counter()
            try:
                with self._session.request(
                    method=method,
                    url=url,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    verify=verify_tls,
                    headers=merged_headers,
                    proxies=self._proxies,
                    stream=True,
                    params=dict(params) if params else None,
                    data=data,
                    json=json_data,
                ) as r:
                    body = b""
                    if max_bytes != 0:
                        chunks: list[bytes] = []
                        total = 0
                        for chunk in r.iter_content(chunk_size=16_384):
                            if not chunk:
                                continue
                            remain = max_bytes - total if max_bytes > 0 else len(chunk)
                            if max_bytes > 0 and remain <= 0:
                                break
                            if max_bytes > 0 and len(chunk) > remain:
                                chunk = chunk[:remain]
                            chunks.append(chunk)
                            total += len(chunk)
                            if max_bytes > 0 and total >= max_bytes:
                                break
                        body = b"".join(chunks)

                    elapsed_ms = int(round((time.perf_counter() - start) * 1000))
                    return HttpResponse(
                        ok=True,
                        url=url,
                        status_code=int(getattr(r, "status_code", 0) or 0),
                        headers=_headers_to_dict(getattr(r, "headers", {})),
                        body=body,
                        response_time_ms=elapsed_ms,
                        error=None,
                    )

            except requests.RequestException as e:
                elapsed_ms = int(round((time.perf_counter() - start) * 1000))
                last_err = f"{type(e).__name__}: {e}"
                if attempt < self.retries:
                    time.sleep(self.backoff * (2 ** attempt))
                    continue
                return HttpResponse(
                    ok=False,
                    url=url,
                    status_code=None,
                    headers={},
                    body=b"",
                    response_time_ms=elapsed_ms,
                    error=last_err,
                )

        return HttpResponse(
            ok=False,
            url=url,
            status_code=None,
            headers={},
            body=b"",
            response_time_ms=None,
            error=last_err or "unknown error",
        )

def body_signature(body: bytes, *, max_len: int = 8192) -> str:
    """
    For SPA fallback heuristics:
    - decode best-effort, lower, collapse whitespace
    - hash prefix
    """
    if not body:
        return ""
    try:
        text = body.decode("utf-8", errors="ignore").lower()
    except Exception:
        text = ""
    text = " ".join(text.split())
    if max_len > 0:
        text = text[:max_len]
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()
