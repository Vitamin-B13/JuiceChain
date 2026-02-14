from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from juicechain.core.alive import check_http_alive


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    # silence default logging
    def log_message(self, format, *args):
        return


def _run_server(server: HTTPServer):
    server.serve_forever(poll_interval=0.1)


def test_check_http_alive_ok():
    server = HTTPServer(("127.0.0.1", 0), _Handler)  # 0 => random free port
    host, port = server.server_address

    t = threading.Thread(target=_run_server, args=(server,), daemon=True)
    t.start()

    try:
        res = check_http_alive(f"http://{host}:{port}", timeout=1.0)
        assert res["alive"] is True
        assert res["status_code"] == 200
        assert isinstance(res["response_time_ms"], int)
        assert res["error"] is None
    finally:
        server.shutdown()
        server.server_close()


def test_check_http_alive_invalid_url():
    res = check_http_alive("http://", timeout=1.0)
    assert res["alive"] is False
    assert res["status_code"] is None
    assert res["error"] is not None
