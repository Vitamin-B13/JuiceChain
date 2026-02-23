from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from juicechain.core.enumeration import enumerate_attack_surface


class _Handler(BaseHTTPRequestHandler):
    server_version = "TestServer/1.0"
    sys_version = ""

    def do_GET(self):
        # IMPORTANT: check /admin BEFORE /a, and make /a matching strict.
        if self.path == "/admin" or self.path.startswith("/admin?") or self.path.startswith("/admin/"):
            self.send_response(403)
            self.end_headers()
            return

        if self.path == "/" or self.path.startswith("/?"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"""
                <html>
                  <head><title>Home</title></head>
                  <body>
                    <a href="/a">PageA</a>
                    <a href="/b?x=1&y=2">PageB</a>
                    <a href="https://example.com/external">External</a>
                    <a href="/#/administration">HashRoute</a>
                  </body>
                </html>
                """
            )
            return

        # strict /a match so it never matches /admin
        if self.path == "/a" or self.path.startswith("/a?") or self.path.startswith("/a/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                b"""
                <html>
                  <head><title>A</title></head>
                  <body>
                    <form action="/submit" method="post">
                      <input name="username"/>
                      <input name="password"/>
                    </form>
                  </body>
                </html>
                """
            )
            return

        if self.path.startswith("/b"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><head><title>B</title></head><body>ok</body></html>")
            return

        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /secret\n")
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return


def _run(server: HTTPServer):
    server.serve_forever(poll_interval=0.1)


def test_enumerate_attack_surface_basic():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    host, port = server.server_address

    t = threading.Thread(target=_run, args=(server,), daemon=True)
    t.start()

    try:
        res = enumerate_attack_surface(f"{host}:{port}", timeout=1.0, max_pages=10)

        assert res["ok"] is True
        crawler = res["crawler"]
        assert crawler is not None
        assert len(crawler["pages_fetched"]) >= 1

        urls = set(crawler["urls_discovered"])
        assert any(u.endswith("/a") for u in urls)
        assert any("/b" in u for u in urls)

        assert "x" in crawler["param_names"]
        assert "y" in crawler["param_names"]

        forms = crawler["forms"]
        assert any(("username" in f["inputs"]) and ("password" in f["inputs"]) for f in forms)

        assert "/#/administration" in crawler["hash_routes"]

        content = res["content_discovery"]
        found_paths = {f["path"]: f["status_code"] for f in content["findings"]}
        assert "/admin" in found_paths
        assert found_paths["/admin"] == 403

    finally:
        server.shutdown()
        server.server_close()