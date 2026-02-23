from __future__ import annotations

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

from juicechain.core.alive import check_http_alive


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        return


def _run_server(server: HTTPServer):
    server.serve_forever()


def test_alive_ok():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=_run_server, args=(server,), daemon=True)
    t.start()
    host, port = server.server_address
    try:
        res = check_http_alive(f"http://{host}:{port}", timeout=2.0)
        assert res["alive"] is True
        assert res["status_code"] == 200
    finally:
        server.shutdown()