"""Real executable/socket checks for M1. This is NOT the future HTTP E2E suite."""
import argparse
import concurrent.futures
from contextlib import contextmanager
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest
import uuid

parser = argparse.ArgumentParser()
for argument in ("agent", "gateway", "cli", "source"):
    parser.add_argument("--" + argument, required=True)
ARGS, TEST_ARGS = parser.parse_known_args()


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def frame(name=b"test-agent", kind=1):
    return struct.pack("!4sBBHI", b"SHDW", 1, kind, 0, len(name)) + name


def receive_exact(sock, count):
    result = b""
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise AssertionError("unexpected EOF")
        result += chunk
    return result


class Transport(unittest.TestCase):
    def setUp(self):
        # Python 3.14's Windows mkdtemp DACL excludes restricted build tokens.
        # These fixtures contain no secrets: inherit the build directory ACL.
        scratch = Path.cwd().resolve() / "integration-fixtures"
        scratch.mkdir(exist_ok=True)
        self.root = scratch / ("run-" + uuid.uuid4().hex)
        self.root.mkdir(mode=0o777)

        def cleanup():
            if self.root.resolve().parent != scratch.resolve():
                raise RuntimeError("fixture cleanup escaped the build directory")
            shutil.rmtree(self.root)

        self.addCleanup(cleanup)
        self.counter = 0

    def agent_config(self, port, name="integration-agent", timeout=1000):
        self.counter += 1
        path = self.root / f"agent-{self.counter}.yaml"
        path.write_text(f"transport: local_tcp\nagent:\n  name: {name}\n  gateway_host: 127.0.0.1\n"
                        f"  port: {port}\n  timeout_ms: {timeout}\n", encoding="utf-8")
        return path

    def run_agent(self, path, cli=False):
        command = [ARGS.cli, "agent", "start"] if cli else [ARGS.agent]
        return subprocess.run(command + ["--config", str(path)], capture_output=True, text=True, timeout=5)

    @contextmanager
    def gateway(self, timeout=1000, maximum=64, cli=False):
        port = available_port()
        config = self.root / f"gateway-{port}.yaml"
        config.write_text(f"transport: local_tcp\ngateway:\n  bind_host: 127.0.0.1\n  port: {port}\n"
                          f"  timeout_ms: {timeout}\n  max_connections: {maximum}\n", encoding="utf-8")
        log = self.root / f"gateway-{port}.log"
        command = [ARGS.cli, "gateway", "start"] if cli else [ARGS.gateway]
        with log.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(command + ["--config", str(config)], stdout=output, stderr=output)
            try:
                deadline = time.monotonic() + 5
                while f"listening port={port}" not in log.read_text(encoding="utf-8"):
                    if process.poll() is not None or time.monotonic() > deadline:
                        self.fail("gateway did not start: " + log.read_text(encoding="utf-8"))
                    time.sleep(0.02)
                yield port, process
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                    self.fail("gateway failed to terminate")

    def assert_closed(self, sock):
        try:
            self.assertEqual(sock.recv(1), b"")
        except (ConnectionResetError, ConnectionAbortedError):
            pass

    def test_executables_complete_real_handshake(self):
        with self.gateway() as (port, _):
            result = self.run_agent(self.agent_config(port))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("hello_acknowledged", result.stderr)

    def test_cli_start_and_config_validate(self):
        with self.gateway(cli=True) as (port, _):
            path = self.agent_config(port)
            result = self.run_agent(path, cli=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([ARGS.cli, "config", "validate", "--type", "agent", "--config", str(path)],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_fragmented_frame(self):
        with self.gateway(timeout=3000) as (port, _), socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            packet = frame()
            for byte in packet:
                sock.sendall(bytes([byte]))
            self.assertEqual(receive_exact(sock, len(packet)), frame(kind=2))
            self.assert_closed(sock)

    def test_concurrent_handshakes_are_isolated(self):
        with self.gateway(timeout=3000) as (port, _):
            paths = [self.agent_config(port, f"agent-{index}", 3000) for index in range(16)]
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
                results = list(executor.map(self.run_agent, paths))
            for result in results:
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_malformed_frames_close_and_gateway_recovers(self):
        valid = frame()
        packets = [b"NOPE" + valid[4:], valid[:4] + b"\x02" + valid[5:],
                   valid[:5] + b"\xff" + valid[6:], valid[:6] + b"\x00\x01" + valid[8:],
                   valid[:8] + struct.pack("!I", 0), valid[:8] + struct.pack("!I", 257),
                   valid[:8] + struct.pack("!I", 0xFFFFFFFF), frame(kind=2), frame(b"bad\nname"),
                   frame(b"x" * 65), frame(b"a\x00b")]
        with self.gateway() as (port, process):
            for packet in packets:
                with self.subTest(packet=packet), socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                    sock.sendall(packet)
                    self.assert_closed(sock)
            self.assertIsNone(process.poll())
            self.assertEqual(self.run_agent(self.agent_config(port)).returncode, 0)

    def test_stalled_and_truncated_clients_release_slots(self):
        with self.gateway(timeout=200, maximum=1) as (port, _):
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                start = time.monotonic()
                sock.sendall(b"SH")
                self.assert_closed(sock)
                self.assertGreater(time.monotonic() - start, 0.1)
            with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
                sock.sendall(frame()[:14])
            time.sleep(0.05)
            self.assertEqual(self.run_agent(self.agent_config(port)).returncode, 0)

    def test_connection_cap_and_recovery(self):
        with self.gateway(timeout=1500, maximum=1) as (port, _):
            with socket.create_connection(("127.0.0.1", port), timeout=2) as first:
                first.sendall(b"SH")
                time.sleep(0.05)
                with socket.create_connection(("127.0.0.1", port), timeout=2) as second:
                    self.assert_closed(second)
            time.sleep(0.05)
            self.assertEqual(self.run_agent(self.agent_config(port)).returncode, 0)

    def test_agent_refuses_missing_gateway(self):
        result = self.run_agent(self.agent_config(available_port()))
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("hello_acknowledged", result.stderr)

    def test_agent_rejects_wrong_ack_disconnect_and_timeout(self):
        for behavior in ("wrong_name", "wrong_type", "disconnect", "timeout"):
            with self.subTest(behavior=behavior), socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(3)
                errors = []

                def server():
                    try:
                        with listener.accept()[0] as sock:
                            sock.settimeout(3)
                            header = receive_exact(sock, 12)
                            receive_exact(sock, struct.unpack("!I", header[8:])[0])
                            if behavior == "wrong_name":
                                sock.sendall(frame(b"different-agent", kind=2))
                            elif behavior == "wrong_type":
                                sock.sendall(frame(b"integration-agent", kind=1))
                            elif behavior == "timeout":
                                time.sleep(0.5)
                    except Exception as error:
                        errors.append(error)

                worker = threading.Thread(target=server, daemon=True)
                worker.start()
                result = self.run_agent(self.agent_config(listener.getsockname()[1], timeout=200))
                worker.join(timeout=4)
                self.assertFalse(worker.is_alive())
                self.assertEqual(errors, [])
                self.assertNotEqual(result.returncode, 0)

    def test_no_fake_cli_commands(self):
        for command in (["agent", "status"], ["agent", "stop"], ["tunnel", "status"], ["service", "list"], []):
            result = subprocess.run([ARGS.cli] + command, capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 2)
        result = subprocess.run([ARGS.cli, "version"], capture_output=True, text=True, timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertIn("0.1.0", result.stdout)

    @unittest.skipIf(sys.platform == "win32", "Windows process.terminate does not deliver POSIX signals")
    def test_graceful_shutdown_closes_active_session(self):
        with self.gateway() as (port, process), socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.sendall(b"SH")
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=3), 0)
            self.assert_closed(sock)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + TEST_ARGS, verbosity=2)
