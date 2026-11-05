"""Bounded HTTP fixture with distinct service identities and adversarial replies."""
import base64
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time
from urllib.parse import urlparse, parse_qs


class Backend(ThreadingHTTPServer):
    request_queue_size = 128
    def __init__(self, label):
        super().__init__(("127.0.0.1", 0), Handler)
        self.label = label
        self.records = []
        self.lock = threading.Lock()
        self.worker = threading.Thread(target=self.serve_forever, daemon=True)
        self.worker.start()

    def count(self):
        with self.lock:
            return len(self.records)

    def stop(self):
        self.shutdown()
        self.server_close()
        self.worker.join(timeout=3)

    def handle_error(self, *_):
        pass  # Cancellation intentionally causes broken pipes in delayed replies.


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_request(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1048576:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        with self.server.lock:
            self.server.records.append((self.command, self.path, body))
        parsed = urlparse(self.path)
        delay = int(parse_qs(parsed.query).get("delay", ["0"])[0])
        if delay:
            time.sleep(min(delay, 3000) / 1000)
        path = parsed.path
        if path == "/malformed":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nBad Header: broken\r\nContent-Length: 0\r\n\r\n")
            self.close_connection = True
            return
        if path == "/ambiguous":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
            self.close_connection = True
            return
        if path == "/oversize":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n")
            self.close_connection = True
            return
        if path == "/huge-header":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 17000 + b"\r\nContent-Length: 0\r\n\r\n")
            self.close_connection = True
            return
        if path == "/chunked":
            self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n"
                             b"Connection: close, X-Internal\r\nX-Internal: private\r\n\r\n"
                             b"2\r\na\x00\r\n3\r\nxyz\r\n0\r\nX-End: final\r\n\r\n")
            self.close_connection = True
            return
        if path == "/eof":
            self.wfile.write(b"HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nbody\x00until-eof")
            self.close_connection = True
            return
        if path == "/transfer-gzip":
            encoded = gzip.compress(b"transfer-coded", mtime=0)
            self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n" +
                             f"{len(encoded):x}\r\n".encode() + encoded + b"\r\n0\r\n\r\n")
            self.close_connection = True
            return
        status, reason = (201, "Created Here") if path == "/cookies" else (200, "OK")
        if path.startswith("/status/"):
            status = int(path.rsplit("/", 1)[1])
            reason = None
        if path == "/interim":
            self.wfile.write(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
        if path == "/fixed":
            payload = ("hello-" + self.server.label).encode()
        elif path in ("/binary", "/gzip"):
            payload = body if self.command != "GET" else bytes(range(256))
            if path == "/gzip":
                payload = gzip.compress(payload, mtime=0)
        else:
            payload = json.dumps({"service": self.server.label, "method": self.command, "path": self.path,
                                  "body": base64.b64encode(body).decode(), "headers": list(self.headers.items())}).encode()
        if status in (204, 304):
            payload = b""
        self.send_response(status, reason)
        self.send_header("Content-Type", "application/octet-stream" if path in ("/binary", "/gzip") else "application/json")
        self.send_header("X-Service", self.server.label)
        self.send_header("X-End-To-End", "preserved")
        self.send_header("Connection", "close, X-Internal")
        self.send_header("X-Internal", "private")
        if path == "/cookies":
            self.send_header("Set-Cookie", "a=1; HttpOnly")
            self.send_header("Set-Cookie", "b=2; Secure")
        if path == "/gzip":
            self.send_header("Content-Encoding", "gzip")
        if status != 204:
            self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = handle_request

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *_):
        pass
