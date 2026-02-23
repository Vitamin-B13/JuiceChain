from __future__ import annotations

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from juicechain.core.enumeration import crawl_site, dir_bruteforce, enumerate_attack_surface


INDEX = b"""
<html>
  <head>
    <title>Index</title>
    <script src="/main.js"></script>
  </head>
  <body>
    <div id="app"></div>
  </body>
</html>
"""

# Routes & endpoints are in JS (typical SPA)
MAIN_JS = b"""
const routes = ['#/login', '#/register', '/#/jobs'];
const api = '/rest/user/login';
const other = '/assets/public/logo.png';
"""

ROBOTS = b"User-agent: *\nDisallow: /secret\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(ROBOTS)
            return

        if self.path == "/main.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(MAIN_JS)
            return

        if self.path == "/" or self.path == "":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            # put a route hint in header too
            self.send_header("X-Recruiting", "/#/jobs")
            self.end_headers()
            self.wfile.write(INDEX)
            return

        # SPA fallback: unknown paths -> same index with 200
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(INDEX)

    def log_message(self, format, *args):
        return


def _run_server(server: HTTPServer):
    server.serve_forever()


def test_crawl_site_spa_assets_and_routes():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=_run_server, args=(server,), daemon=True)
    t.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        res = crawl_site(base, timeout=2.0, max_pages=5, fetch_spa_assets=True, max_spa_assets=3)
        spa = res.get("spa") or {}
        assert any(u.endswith("/main.js") for u in (spa.get("asset_urls") or []))
        routes = set(spa.get("routes_from_assets") or [])
        assert "#/login" in routes
        assert "#/register" in routes
        # from header
        assert "#/jobs" in set(res.get("hash_routes") or [])
        api = set(spa.get("api_candidates_from_assets") or [])
        assert "/rest/user/login" in api
    finally:
        server.shutdown()


def test_dir_bruteforce_spa_route_classification():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=_run_server, args=(server,), daemon=True)
    t.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        # Provide extracted spa routes to mapper
        spa_routes = ["#/login", "#/register"]
        res = dir_bruteforce(base, ["/login", "/not-a-route"], timeout=2.0, spa_routes=spa_routes)
        spa_found = res.get("findings_spa_routes") or []
        noise = res.get("findings_fallback_noise") or []
        assert any(f["path"] == "/login" for f in spa_found)
        assert any(f["path"] == "/not-a-route" for f in noise)
    finally:
        server.shutdown()


def test_enumerate_attack_surface_ok():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=_run_server, args=(server,), daemon=True)
    t.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        res = enumerate_attack_surface(base, timeout=2.0, max_pages=5, paths=["/robots.txt", "/login", "/abc"])
        assert res["ok"] is True
        cd = res["content_discovery"]
        assert cd["findings_server_endpoints"]  # robots
        assert cd["findings_spa_routes"]        # login
    finally:
        server.shutdown()