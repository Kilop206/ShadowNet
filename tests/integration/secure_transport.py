"""Real TLS 1.3/mTLS/WSS processes and adversarial peers; standard library only."""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import unittest
import uuid
from contextlib import contextmanager

parser = argparse.ArgumentParser()
for argument in ("agent", "gateway", "cli", "source", "openssl"):
    parser.add_argument("--" + argument, required=True)
ARGS, TEST_ARGS = parser.parse_known_args()


def port_available():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError("peer closed")
        data += part
    return data


def packet(kind=1, payload=b"home-server", version=2):
    return struct.pack("!4sBBHI", b"SHDW", version, kind, 0, len(payload)) + payload


def send_ws(sock, data, opcode=2, masked=True):
    header = bytes([0x80 | opcode])
    length = len(data)
    marker = 0x80 if masked else 0
    header += bytes([marker | length]) if length < 126 else bytes([marker | 126]) + struct.pack("!H", length)
    if masked:
        mask = secrets.token_bytes(4)
        data = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
        header += mask
    sock.sendall(header + data)


def receive_ws(sock):
    header = exact(sock, 2)
    size = header[1] & 127
    if size == 126:
        size = struct.unpack("!H", exact(sock, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", exact(sock, 8))[0]
    if size > 4096:
        raise AssertionError("unbounded server frame")
    mask = exact(sock, 4) if header[1] & 128 else None
    data = exact(sock, size)
    if mask:
        data = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
    return header[0] & 15, data


def http_header(sock):
    result = b""
    while not result.endswith(b"\r\n\r\n"):
        result += exact(sock, 1)
        if len(result) > 8192:
            raise AssertionError("oversized upgrade header")
    return result


class Background:
    def __init__(self, command, path):
        self.path = path
        self.output = path.open("w", encoding="utf-8")
        self.process = subprocess.Popen(command, stdout=self.output, stderr=self.output)

    def log(self):
        return self.path.read_text(encoding="utf-8", errors="replace")

    def wait_log(self, event, count=1, timeout=6):
        deadline = time.monotonic() + timeout
        while self.log().count(event) < count:
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise AssertionError("missing event " + event + ": " + self.log())
            time.sleep(0.02)

    def stop(self, hard=False):
        if self.process.poll() is None:
            self.process.kill() if hard else self.process.terminate()
        try:
            self.process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
            raise AssertionError("process did not stop")
        self.output.close()


class SecureTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path.cwd().resolve() / ("wss-fixtures-" + uuid.uuid4().hex)
        cls.addClassCleanup(cls.cleanup_fixtures)
        spec = importlib.util.spec_from_file_location("shadow_dev_pki", Path(ARGS.source) / "scripts/dev-certificates.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.fingerprint = module.generate(cls.root, ARGS.openssl, test_fixtures=True)

    @classmethod
    def cleanup_fixtures(cls):
        if cls.root.parent != Path.cwd().resolve() or not cls.root.name.startswith("wss-fixtures-"):
            raise RuntimeError("unsafe fixture cleanup path")
        if cls.root.exists():
            shutil.rmtree(cls.root)

    def setUp(self):
        self.working = self.root / uuid.uuid4().hex
        self.working.mkdir()
        self.counter = 0
        self.children = []
        self.addCleanup(self.cleanup_processes)

    def cleanup_processes(self):
        for child in reversed(self.children):
            child.stop()

    def security(self, profile, trust="ca"):
        path = lambda name: json.dumps((self.root / name).as_posix())
        return ("security:\n  ca_file: " + path(trust + ".crt") + "\n  certificate_file: " + path(profile + ".crt") +
                "\n  private_key_file: " + path(profile + ".key") + "\n")

    def write_config(self, text):
        self.counter += 1
        path = self.working / f"config-{self.counter}.yaml"
        path.write_text(text, encoding="utf-8")
        return path

    def agent_config(self, port, reconnect=False, profile="agent", trust="ca", name="home-server", timeout=1500):
        return self.write_config(f"transport: wss\nagent:\n  name: {name}\n  gateway_host: 127.0.0.1\n  port: {port}\n"
                                 f"  timeout_ms: {timeout}\n  reconnect:\n    enabled: {str(reconnect).lower()}\n"
                                 "    initial_ms: 100\n    max_ms: 400\n" + self.security(profile, trust))

    def gateway_config(self, port, profile="gateway", maximum=16, timeout=1500, authorize_other=False):
        authorized = "authorized_agents:\n  - name: home-server\n    certificate_sha256: " + self.fingerprint + "\n"
        if authorize_other:
            other = hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.root / "other-agent.crt").read_text())).hexdigest()
            authorized += "  - name: second-agent\n    certificate_sha256: " + other + "\n"
        return self.write_config(f"transport: wss\ngateway:\n  bind_host: 127.0.0.1\n  port: {port}\n  timeout_ms: {timeout}\n"
                                f"  max_connections: {maximum}\n  heartbeat_interval_ms: 100\n  heartbeat_timeout_ms: 400\n" +
                                self.security(profile) + authorized)

    def start(self, executable, path):
        self.counter += 1
        child = Background([executable, "--config", str(path)], self.working / f"process-{self.counter}.log")
        self.children.append(child)
        return child

    def gateway(self, port=None, **options):
        port = port or port_available()
        child = self.start(ARGS.gateway, self.gateway_config(port, **options))
        child.wait_log("wss_listening")
        return port, child

    def once(self, path):
        return subprocess.run([ARGS.agent, "--config", str(path)], capture_output=True, text=True, timeout=5)

    def tls(self, port, profile="agent", trust="ca", hostname="127.0.0.1", maximum=ssl.TLSVersion.TLSv1_3):
        context = ssl.create_default_context(cafile=str(self.root / (trust + ".crt")))
        context.minimum_version = maximum
        context.maximum_version = maximum
        if profile:
            context.load_cert_chain(self.root / (profile + ".crt"), self.root / (profile + ".key"))
        raw = socket.create_connection(("127.0.0.1", port), timeout=3)
        try:
            return context.wrap_socket(raw, server_hostname=hostname)
        except Exception:
            raw.close()
            raise

    @contextmanager
    def websocket(self, port, profile="agent", path="/shadow/tunnel/v2", protocol="shadownet.v2", origin=False):
        with self.tls(port, profile) as sock:
            self.assertEqual(sock.version(), "TLSv1.3")
            key = base64.b64encode(secrets.token_bytes(16)).decode()
            request = (f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                       f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {protocol}\r\n")
            if origin:
                request += "Origin: https://example.test\r\n"
            sock.sendall((request + "\r\n").encode())
            response = http_header(sock)
            self.assertIn(b"101 Switching Protocols", response)
            expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
            self.assertIn(expected, response)
            self.assertIn(b"Sec-WebSocket-Protocol: shadownet.v2", response)
            yield sock

    def hello(self, sock, name=b"home-server"):
        send_ws(sock, packet(payload=name))
        opcode, data = receive_ws(sock)
        self.assertEqual(opcode, 2)
        self.assertEqual(data[:8], b"SHDW\x02\x02\x00\x00")
        self.assertEqual(struct.unpack("!I", data[8:12])[0], len(data) - 12)
        nonce, interval, timeout = data[12:].decode().split(":")
        self.assertRegex(nonce, r"^[0-9a-f]{32}$")
        self.assertEqual((interval, timeout), ("100", "400"))
        return nonce

    def rejected(self, action):
        try:
            action()
        except (ssl.SSLError, EOFError, ConnectionError):
            return
        self.fail("invalid peer was accepted")

    def assert_ws_closed(self, sock):
        try:
            opcode, _ = receive_ws(sock)
            self.assertEqual(opcode, 8, "invalid traffic received a data response")
        except (ssl.SSLError, EOFError, ConnectionError):
            pass

    def test_real_agent_negotiates_and_maintains_heartbeat(self):
        port, _ = self.gateway()
        agent = self.start(ARGS.agent, self.agent_config(port))
        agent.wait_log("heartbeat_confirmed", count=3)
        self.assertIsNone(agent.process.poll())

    def test_reconnect_uses_bounded_exponential_jitter(self):
        agent = self.start(ARGS.agent, self.agent_config(port_available(), reconnect=True))
        agent.wait_log("reconnect_scheduled", count=4, timeout=12)
        delays = list(map(int, re.findall(r"reconnect_scheduled delay_ms=(\d+)", agent.log())))[:4]
        for delay, bounds in zip(delays, ((50, 100), (100, 200), (200, 400), (200, 400))):
            self.assertGreaterEqual(delay, bounds[0])
            self.assertLessEqual(delay, bounds[1])

    def test_agent_recovers_when_gateway_appears(self):
        port = port_available()
        agent = self.start(ARGS.agent, self.agent_config(port, reconnect=True))
        agent.wait_log("reconnect_scheduled")
        self.gateway(port)
        agent.wait_log("heartbeat_confirmed")

    def test_reconnect_after_gateway_restart_has_new_session(self):
        port, gateway = self.gateway()
        agent = self.start(ARGS.agent, self.agent_config(port, reconnect=True))
        agent.wait_log("heartbeat_confirmed")
        gateway.stop(hard=True)
        agent.wait_log("reconnect_scheduled")
        self.gateway(port)
        agent.wait_log("tunnel_established", count=2)
        agent.wait_log("heartbeat_confirmed", count=2)
        sessions = re.findall(r"tunnel_established session=([0-9a-f]{32})", agent.log())
        self.assertEqual(len(set(sessions)), 2)

    def test_missing_foreign_expired_and_wrong_purpose_client_certificates_fail(self):
        port, gateway = self.gateway()
        for profile in (None, "rogue-agent", "expired-agent", "wrong-purpose"):
            with self.subTest(profile=profile):
                def attempt():
                    with self.tls(port, profile) as sock:
                        sock.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        if not sock.recv(1):
                            raise EOFError()
                self.rejected(attempt)
        self.assertNotIn("tunnel_established", gateway.log())

    def test_trusted_but_unauthorized_client_fingerprint_fails(self):
        port, gateway = self.gateway()
        def attempt():
            with self.websocket(port, profile="other-agent"):
                pass
        self.rejected(attempt)
        gateway.wait_log("agent_not_authorized")
        with self.websocket(port) as sock:
            self.hello(sock)

    def test_tls12_is_rejected(self):
        port, _ = self.gateway()
        self.rejected(lambda: self.tls(port, maximum=ssl.TLSVersion.TLSv1_2))

    def test_agent_rejects_wrong_gateway_hostname_and_ca(self):
        port, _ = self.gateway(profile="wrong-host")
        result = self.once(self.agent_config(port))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("tls_handshake_failed", result.stderr)
        port, _ = self.gateway()
        result = self.once(self.agent_config(port, trust="rogue-ca"))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("tls_handshake_failed", result.stderr)

    def test_hello_must_match_certificate_authorization(self):
        port, gateway = self.gateway()
        with self.websocket(port) as sock:
            send_ws(sock, packet(payload=b"someone-else"))
            self.assert_ws_closed(sock)
        self.assertNotIn("tunnel_established", gateway.log())

    def test_duplicate_identity_does_not_replace_active_agent(self):
        port, _ = self.gateway()
        agent = self.start(ARGS.agent, self.agent_config(port))
        agent.wait_log("heartbeat_confirmed")
        duplicate = self.once(self.agent_config(port))
        self.assertEqual(duplicate.returncode, 1)
        agent.wait_log("heartbeat_confirmed", count=3)
        self.assertIsNone(agent.process.poll())

    def test_two_authorized_identities_have_independent_sessions(self):
        port, _ = self.gateway(authorize_other=True)
        first = self.start(ARGS.agent, self.agent_config(port))
        second = self.start(ARGS.agent, self.agent_config(port, profile="other-agent", name="second-agent"))
        first.wait_log("heartbeat_confirmed", count=2)
        second.wait_log("heartbeat_confirmed", count=2)
        self.assertNotEqual(re.search(r"session=([0-9a-f]+)", first.log())[1], re.search(r"session=([0-9a-f]+)", second.log())[1])

    def test_invalid_websocket_path_subprotocol_and_browser_origin_fail(self):
        port, gateway = self.gateway()
        for options in ({"path": "/"}, {"protocol": "shadownet.v1"}, {"origin": True}):
            with self.subTest(options=options):
                def attempt():
                    with self.websocket(port, **options):
                        pass
                self.rejected(attempt)
        self.assertNotIn("tunnel_established", gateway.log())

    def test_malformed_oversized_and_text_frames_close(self):
        port, gateway = self.gateway()
        cases = [(packet(version=1), 2), (packet(kind=255), 2), (packet(payload=b"bad name"), 2),
                 (packet() + b"trailing", 2), (b"x" * 300, 2), (packet(), 1),
                 (packet(kind=3, payload=b"0000000000000001"), 2)]
        for data, opcode in cases:
            with self.subTest(data=data[:20], opcode=opcode), self.websocket(port) as sock:
                send_ws(sock, data, opcode)
                self.assert_ws_closed(sock)
        self.assertIsNone(gateway.process.poll())
        with self.websocket(port) as sock:
            self.hello(sock)

    def test_heartbeat_replay_and_missing_ping_are_rejected(self):
        port, gateway = self.gateway()
        with self.websocket(port) as sock:
            self.hello(sock)
            send_ws(sock, packet(kind=3, payload=b"0000000000000001"))
            self.assertEqual(receive_ws(sock), (2, packet(kind=4, payload=b"0000000000000001")))
            send_ws(sock, packet(kind=3, payload=b"0000000000000001"))
            self.assert_ws_closed(sock)
        with self.websocket(port) as sock:
            self.hello(sock)
            self.assert_ws_closed(sock)
        gateway.wait_log("heartbeat_timeout")

    def test_peer_goodbye_performs_websocket_and_tls_shutdown(self):
        port, gateway = self.gateway()
        with self.websocket(port) as sock:
            self.hello(sock)
            send_ws(sock, packet(kind=5, payload=b"shutdown"))
            opcode, close = receive_ws(sock)
            self.assertEqual(opcode, 8)
            send_ws(sock, close, opcode=8)
            plain = sock.unwrap()  # Requires the gateway's TLS close_notify.
            plain.close()
        gateway.wait_log("tunnel_closed")

    def test_deadline_covers_tcp_tls_and_initial_hello(self):
        port, gateway = self.gateway(timeout=200)
        with socket.create_connection(("127.0.0.1", port), timeout=2) as raw:
            self.assertEqual(raw.recv(1), b"")
        with self.websocket(port) as sock:
            self.assert_ws_closed(sock)
        gateway.wait_log("handshake_timeout", count=2)

    def test_connection_limit_releases_after_failed_tls(self):
        port, gateway = self.gateway(maximum=1, timeout=1000)
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            time.sleep(0.05)
            self.rejected(lambda: self.tls(port))
        gateway.wait_log("connection_limit_reached")
        time.sleep(0.05)
        with self.websocket(port) as sock:
            self.hello(sock)

    @contextmanager
    def fake_gateway(self, behavior, profile="gateway"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.root / "ca.crt")
        context.load_cert_chain(self.root / (profile + ".crt"), self.root / (profile + ".key"))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(4)
            errors = []

            def serve():
                try:
                    with listener.accept()[0] as raw, context.wrap_socket(raw, server_side=True) as peer:
                        peer.settimeout(3)
                        if profile == "expired-gateway":
                            peer.recv(1)
                            return
                        request = http_header(peer).decode()
                        key = re.search(r"Sec-WebSocket-Key: ([^\r]+)", request, re.IGNORECASE)[1]
                        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                        peer.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                      f"Sec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: shadownet.v2\r\n\r\n").encode())
                        receive_ws(peer)  # HELLO
                        if behavior == "no_welcome":
                            peer.recv(1)
                            return
                        send_ws(peer, packet(2, b"a" * 32 + b":100:200"), masked=False)
                        opcode, ping = receive_ws(peer)
                        if opcode != 2:
                            raise AssertionError("expected heartbeat")
                        if behavior == "wrong_pong":
                            send_ws(peer, packet(4, b"0000000000000002"), masked=False)
                        peer.recv(1)
                except (ssl.SSLError, EOFError, ConnectionError):
                    pass  # Rejected peers and aborted test sockets are expected.
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=serve, daemon=True)
            worker.start()
            try:
                yield listener.getsockname()[1]
            finally:
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive(), "fake gateway did not stop")
                self.assertEqual(errors, [])

    def test_agent_rejects_expired_gateway_certificate(self):
        with self.fake_gateway("expired", profile="expired-gateway") as port:
            result = self.once(self.agent_config(port))
            self.assertEqual(result.returncode, 1)
            self.assertIn("tls_handshake_failed", result.stderr)

    def test_agent_rejects_wrong_pong_and_times_out_stalled_gateway(self):
        for behavior, event in (("wrong_pong", "invalid_tunnel_message"), ("missing_pong", "heartbeat_timeout"),
                                ("no_welcome", "handshake_timeout")):
            with self.subTest(behavior=behavior), self.fake_gateway(behavior) as port:
                result = self.once(self.agent_config(port, timeout=400))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(event, result.stderr)

    def test_cli_validates_credential_files_key_pairs_and_permissions(self):
        good = self.agent_config(port_available())
        def validate(path):
            return subprocess.run([ARGS.cli, "config", "validate", "--type", "agent", "--config", str(path)],
                                  capture_output=True, text=True, timeout=3)
        self.assertEqual(validate(good).returncode, 0)
        text = good.read_text()
        for modified in (text.replace("agent.key", "gateway.key"), text.replace("agent.crt", "absent.crt"),
                         text.replace("agent.crt", "expired-agent.crt"), text.replace("enabled: false", "enabled: yes"),
                         text.replace("max_ms: 400", "max_ms: 99"), text.replace("initial_ms: 100", "initial_ms: 500"), text + "unknown: true\n",
                         text.replace("security:\n", "security:\n  verify: false\n")):
            with self.subTest(modified=modified[-150:]):
                result = validate(self.write_config(modified))
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("BEGIN PRIVATE KEY", result.stderr)
        if sys.platform != "win32":
            copy = self.working / "insecure.key"
            shutil.copyfile(self.root / "agent.key", copy)
            copy.chmod(0o644)
            modified = text.replace((self.root / "agent.key").as_posix(), copy.as_posix())
            self.assertEqual(validate(self.write_config(modified)).returncode, 1)

    def test_gateway_configuration_rejects_invalid_authorization_and_bounds(self):
        good = self.gateway_config(port_available())
        text = good.read_text()
        modifications = [text.replace(self.fingerprint, "f" * 63), text.replace(self.fingerprint, self.fingerprint.upper()),
                         text.replace("bind_host: 127.0.0.1", "bind_host: localhost"),
                         text.replace("heartbeat_interval_ms: 100", "heartbeat_interval_ms: 99"),
                         text.replace("certificate_file:", "verify: false\n  certificate_file:"),
                         text + "  - name: home-server\n    certificate_sha256: " + "a" * 64 + "\n",
                         text + "  - name: another\n    certificate_sha256: " + self.fingerprint + "\n"]
        for modified in modifications:
            result = subprocess.run([ARGS.cli, "config", "validate", "--type", "gateway", "--config", str(self.write_config(modified))],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    @unittest.skipIf(sys.platform == "win32", "Windows terminate does not deliver SIGTERM")
    def test_graceful_shutdown_closes_wss_tls_and_sessions(self):
        port, gateway = self.gateway()
        agent = self.start(ARGS.agent, self.agent_config(port))
        agent.wait_log("heartbeat_confirmed")
        agent.process.send_signal(signal.SIGTERM)
        self.assertEqual(agent.process.wait(timeout=3), 0)
        gateway.wait_log("tunnel_closed")
        gateway.process.send_signal(signal.SIGTERM)
        self.assertEqual(gateway.process.wait(timeout=3), 0)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + TEST_ARGS, verbosity=2)
