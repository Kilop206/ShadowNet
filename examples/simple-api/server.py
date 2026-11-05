"""Loopback HTTP fixture for the future M3 end-to-end test; no dependencies."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import signal
import threading


class API(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.respond(200, {"service": "shadow-example-api", "path": self.path})

    def do_POST(self):
        # Keep this diagnostic fixture bounded; it is not a production API.
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.respond(400, {"error": "invalid content length"})
            return
        if self.headers.get("Transfer-Encoding") or not 0 <= length <= 65536:
            self.respond(413, {"error": "unsupported or oversized body"})
            return
        body = self.rfile.read(length)
        self.respond(200, {"method": "POST", "body": body.decode("utf-8", errors="replace")})

    def respond(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *_):
        pass  # Do not log arbitrary paths or request data.

    def setup(self):
        super().setup()
        self.connection.settimeout(5)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8080), API)
    # shutdown() must run outside the serve_forever thread. An explicit handler
    # also permits graceful SIGTERM when Python is PID 1 in the example container.
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
