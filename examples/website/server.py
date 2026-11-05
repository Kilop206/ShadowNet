"""A second loopback-only HTTP service for the reverse-proxy demonstration."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import signal
import threading

PAGE = b"""<!doctype html><html lang="en"><meta charset="utf-8">
<title>ShadowNet example website</title><h1>ShadowNet</h1>
<p>Example website published through the secure gateway.</p></html>"""


class Website(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def respond(self, head=False):
        body = PAGE if self.path == "/" else b"Not Found\n"
        self.send_response(200 if self.path == "/" else 404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Service", "website")
        self.send_header("Connection", "close")
        self.end_headers()
        if not head:
            self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        self.respond()

    def do_HEAD(self):
        self.respond(head=True)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 3000), Website)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
