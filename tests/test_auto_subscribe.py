from __future__ import annotations

import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import auto_subscribe


class _MinifluxHandler(BaseHTTPRequestHandler):
    existing = "https://example.com/existing.atom"
    created: list[str] = []

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/":
            assert self.headers["X-Openhost-User"] == "admin"
            self.send_response(302)
            self.send_header("Set-Cookie", "session=anonymous; Path=/; Secure; HttpOnly")
            self.send_header("Set-Cookie", "session=secret; Path=/; Secure; HttpOnly")
            self.send_header("Location", "/unread")
            self.end_headers()
            return

        assert self.headers["Cookie"] == "session=secret"
        if self.path == "/export":
            self._send(200, f'<opml><body><outline xmlUrl="{self.existing}"/></body></opml>')
        elif self.path == "/subscribe":
            self._send(
                200,
                '<form><input name="csrf" value="token">'
                '<select name="category_id"><option value="42">All</option></select></form>',
            )
        else:
            self.send_error(404)

    def do_POST(self):
        assert self.path == "/subscribe"
        assert self.headers["Cookie"] == "session=secret"
        body = self.rfile.read(int(self.headers["Content-Length"]))
        fields = urllib.parse.parse_qs(body.decode())
        assert fields["csrf"] == ["token"]
        assert fields["category_id"] == ["42"]
        self.created.append(fields["url"][0])
        self.send_response(302)
        self.send_header("Location", "/feed/7/entries")
        self.end_headers()

    def _send(self, status: int, body: str):
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def test_subscribe_skips_existing_feeds_and_creates_missing_feeds():
    _MinifluxHandler.created = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MinifluxHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        auto_subscribe.subscribe(
            [_MinifluxHandler.existing, "https://example.com/new.atom"],
            f"http://127.0.0.1:{server.server_port}",
        )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert _MinifluxHandler.created == ["https://example.com/new.atom"]
