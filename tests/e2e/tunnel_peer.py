"""Independent binary/WSS peer used for authorization and correlation tests."""
import base64
import hashlib
import secrets
import socket
import ssl
import struct


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise EOFError("peer closed")
        result.extend(part)
    return bytes(result)


def header(sock):
    result = b""
    while not result.endswith(b"\r\n\r\n"):
        result += exact(sock, 1)
        if len(result) > 8192:
            raise AssertionError("oversized HTTP upgrade")
    return result


def text(value):
    data = value.encode() if isinstance(value, str) else value
    return struct.pack("!H", len(data)) + data


def services(entries):
    return struct.pack("!H", len(entries)) + b"".join(text(name) + text(host) for name, host in entries)


def request(identifier, service, host, target="/fixed", method="GET"):
    return struct.pack("!Q", identifier) + text(service) + text(method) + text(target) + struct.pack("!H", 1) + text("host") + text(host) + struct.pack("!I", 0)


def response(identifier, body=b"correct"):
    return struct.pack("!QH", identifier, 200) + text("OK") + struct.pack("!HI", 0, len(body)) + body


class Peer:
    def __init__(self, sock, client=True):
        self.sock = sock
        self.client = client

    @classmethod
    def connect(cls, root, port, profile="agent", name="home-server"):
        context = ssl.create_default_context(cafile=str(root / "ca.crt"))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(root / (profile + ".crt"), root / (profile + ".key"))
        raw = socket.create_connection(("127.0.0.1", port), timeout=4)
        sock = context.wrap_socket(raw, server_hostname="127.0.0.1")
        key = base64.b64encode(secrets.token_bytes(16)).decode()
        sock.sendall(("GET /shadow/tunnel/v3 HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: shadownet.v3\r\n\r\n").encode())
        upgrade = header(sock)
        assert b"101 Switching Protocols" in upgrade
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        assert expected in upgrade
        peer = cls(sock)
        peer.send(1, name.encode())
        assert peer.receive()[0] == 2
        return peer

    @classmethod
    def accept(cls, sock):
        upgrade = header(sock).decode()
        key = next(line.split(":", 1)[1].strip() for line in upgrade.split("\r\n") if line.lower().startswith("sec-websocket-key:"))
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        sock.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: shadownet.v3\r\n\r\n").encode())
        peer = cls(sock, client=False)
        assert peer.receive()[0] == 1
        peer.send(2, b"a" * 32 + b":1000:3000")
        return peer

    def send(self, kind, payload):
        message = struct.pack("!4sBBHI", b"SHDW", 3, kind, 0, len(payload)) + payload
        size = len(message)
        marker = 128 if self.client else 0
        head = b"\x82" + (bytes([marker | size]) if size < 126 else
                            bytes([marker | 126]) + struct.pack("!H", size) if size < 65536 else
                            bytes([marker | 127]) + struct.pack("!Q", size))
        if self.client:
            mask = secrets.token_bytes(4)
            head += mask
            message = bytes(value ^ mask[index % 4] for index, value in enumerate(message))
        self.sock.sendall(head + message)

    def receive(self):
        message = bytearray()
        initial = True
        while True:
            first = exact(self.sock, 2)
            if first[0] & 15 not in (2 if initial else 0,):
                raise EOFError("peer sent a close/control frame")
            initial = False
            size = first[1] & 127
            if size == 126:
                size = struct.unpack("!H", exact(self.sock, 2))[0]
            elif size == 127:
                size = struct.unpack("!Q", exact(self.sock, 8))[0]
            assert len(message) + size <= 1081356
            mask = exact(self.sock, 4) if first[1] & 128 else None
            part = exact(self.sock, size)
            if mask:
                part = bytes(value ^ mask[index % 4] for index, value in enumerate(part))
            message.extend(part)
            if first[0] & 128:
                break
        data = bytes(message)
        assert data[:5] == b"SHDW\x03" and len(data) == 12 + struct.unpack("!I", data[8:12])[0]
        return data[5], data[12:]

    def data(self):
        while True:
            kind, payload = self.receive()
            if kind == 3:
                self.send(4, payload)
            else:
                return kind, payload

    def close(self):
        self.sock.close()
