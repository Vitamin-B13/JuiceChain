from juicechain.core.enumeration import (
    _scan_generic_paths_from_js,
    _scan_react_routes_from_js,
    _scan_vue_routes_from_js,
)


def test_scan_react_routes_from_js_common_patterns():
    js = """
    <Route path="/users/:id" element={<User />} />
    const routes = [{ path: "/dashboard" }, { path: '/settings' }];
    <Link to="/orders">Orders</Link>
    const go = navigate("/checkout");
    useNavigate()('/profile');
    const linkCfg = { to: '/cart' };
    """
    routes = _scan_react_routes_from_js(js)
    assert "/users/:id" in routes
    assert "/dashboard" in routes
    assert "/settings" in routes
    assert "/orders" in routes
    assert "/checkout" in routes
    assert "/profile" in routes
    assert "/cart" in routes


def test_scan_react_routes_from_js_empty_or_no_match():
    assert _scan_react_routes_from_js("") == set()
    assert _scan_react_routes_from_js("const msg = 'hello world';") == set()


def test_scan_vue_routes_from_js_common_patterns():
    js = """
    const routes = [
      { path: '/users/:id', name: 'user-detail' },
      { path: "/reports", name: "reports" },
    ];
    this.$router.push('/account');
    router.push("/billing");
    """
    routes = _scan_vue_routes_from_js(js)
    assert "/users/:id" in routes
    assert "/reports" in routes
    assert "/account" in routes
    assert "/billing" in routes
    assert "/user-detail" in routes


def test_scan_vue_routes_from_js_empty_or_no_match():
    assert _scan_vue_routes_from_js("") == set()
    assert _scan_vue_routes_from_js("const x = 1; function hi() {}") == set()


def test_scan_generic_paths_from_js_extracts_paths_and_dynamic_params():
    js = """
    const a = "/login";
    const b = '/products/:id';
    const c = "/search/results";
    """
    routes = _scan_generic_paths_from_js(js)
    assert "/login" in routes
    assert "/products/:id" in routes
    assert "/search/results" in routes


def test_scan_generic_paths_from_js_filters_static_internal_and_invalid():
    very_long = "/" + ("a" * 81)
    js = f"""
    const a = "/assets/app.js";
    const b = "/static/main.css";
    const c = "/images/logo.png";
    const d = "/node_modules/react/index";
    const e = "/webpack/runtime";
    const f = "/__webpack_require__";
    const g = "{very_long}";
    const h = "/bad<path>";
    const ok = "/valid/path";
    """
    routes = _scan_generic_paths_from_js(js)
    assert "/valid/path" in routes
    assert "/assets/app.js" not in routes
    assert "/static/main.css" not in routes
    assert "/images/logo.png" not in routes
    assert "/node_modules/react/index" not in routes
    assert "/webpack/runtime" not in routes
    assert "/__webpack_require__" not in routes
    assert very_long not in routes
    assert "/bad<path>" not in routes


def test_scan_generic_paths_from_js_empty_or_no_match():
    assert _scan_generic_paths_from_js("") == set()
    assert _scan_generic_paths_from_js("const z = 'abc';") == set()
