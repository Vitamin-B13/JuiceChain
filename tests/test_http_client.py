from juicechain.core.http_client import HttpClient


class _FakeResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self.status_code = 200
        self.headers = {"Content-Type": "text/plain"}
        self._chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size: int = 16_384):
        del chunk_size
        for c in self._chunks:
            yield c

    def close(self) -> None:
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        del exc_type, exc, tb
        self.close()
        return False


def test_http_client_closes_streamed_response_on_truncated_read(monkeypatch):
    client = HttpClient(timeout=1.0, max_bytes=3)
    fake = _FakeResponse([b"abcd", b"ef"])

    def _fake_request(**kwargs):
        del kwargs
        return fake

    monkeypatch.setattr(client._session, "request", _fake_request)
    res = client.request("GET", "http://example.test", max_bytes=3)
    client.close()

    assert res.ok is True
    assert res.status_code == 200
    assert res.body == b"abc"
    assert fake.closed is True
