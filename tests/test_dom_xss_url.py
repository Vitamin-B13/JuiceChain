from juicechain.core.dom_xss import build_search_fragment_url


def test_build_search_fragment_url_encodes_payload():
    base = "http://127.0.0.1:3000"
    payload = "<script>alert('XSS')</script>"
    url = build_search_fragment_url(base, payload)
    assert url.startswith(base + "/#/search?q=")
    assert "<" not in url
    assert ">" not in url
    assert "script" in url.lower()