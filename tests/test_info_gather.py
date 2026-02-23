from __future__ import annotations

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from juicechain.core.info_gather import gather_info


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx"
    sys_version = ""

    def do_GET(self):
        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Powered-By", "Express")
        self.end_headers()
        self.wfile.write(b"<html><head><title>Home</title></head><body>Hello</body></html>")

    def log_message(self, format, *args):
        return


def _run_server(server: HTTPServer):
    server.serve_forever()


def test_info_gather_ok():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=_run_server, args=(server,), daemon=True)
    t.start()
    host, port = server.server_address
    try:
        res = gather_info(f"http://{host}:{port}", timeout=2.0)
        assert res["ok"] is True
        assert res["homepage"]["title"] == "Home"
        assert "nginx" in res["fingerprint"]["hints"]
        assert "express" in res["fingerprint"]["hints"]
        assert res["robots"]["ok"] is True
        assert "/admin" in res["robots"]["directives"]["disallow"]
    finally:
        server.shutdown()