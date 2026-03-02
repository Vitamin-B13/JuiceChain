from juicechain.core.dom_xss import DomXssTarget, auto_discover_dom_xss_targets, build_dom_xss_url


def test_build_dom_xss_url_encodes_payload():
    target = DomXssTarget(
        url_template="{base}/#/search?q={payload}",
        param_name="q",
        description="SPA search route",
    )
    url = build_dom_xss_url("http://127.0.0.1:3000", target, "<script>alert('XSS')</script>")
    assert url.startswith("http://127.0.0.1:3000/#/search?q=")
    assert "<" not in url
    assert ">" not in url
    assert "script" in url.lower()


def test_auto_discover_dom_xss_targets_from_routes():
    doc = {
        "enum": {
            "crawler": {
                "spa": {
                    "routes_from_assets": [
                        "#/search",
                        "/#/query",
                        "/products/find",
                        "/administration",
                    ]
                }
            }
        }
    }

    targets = auto_discover_dom_xss_targets(doc)
    keys = {(t.url_template, t.param_name) for t in targets}

    assert ("{base}/#/search?q={payload}", "q") in keys
    assert ("{base}/#/query?q={payload}", "q") in keys
    assert ("{base}/products/find?q={payload}", "q") in keys
    assert all("/administration" not in t.url_template for t in targets)


def test_auto_discover_dom_xss_targets_accepts_extra_targets():
    extra = DomXssTarget(
        url_template="{base}/custom/lookup?term={payload}",
        param_name="term",
        description="manual target",
    )
    targets = auto_discover_dom_xss_targets({}, extra_targets=[extra])
    assert len(targets) == 1
    assert targets[0] == extra
