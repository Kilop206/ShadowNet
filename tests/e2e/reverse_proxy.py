"""HTTPS client -> real Gateway -> WSS/mTLS -> real Agent -> two local HTTP services."""
import argparse
import base64
import concurrent.futures
from contextlib import contextmanager
import gzip
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import unittest
import uuid
from backend import Backend
from tunnel_peer import Peer, services, request as wire_request, response as wire_response

parser = argparse.ArgumentParser()
for argument in ("agent", "gateway", "cli", "source", "openssl"):
    parser.add_argument("--" + argument, required=True)
parser.add_argument("--load-seconds", type=float, default=float(os.environ.get("SHADOW_LOAD_SECONDS", "5")))
parser.add_argument("--load-workers", type=int, default=int(os.environ.get("SHADOW_LOAD_WORKERS", "12")))
parser.add_argument("--load-report", type=Path, default=Path("reliability-load.json"))
ARGS, TEST_ARGS = parser.parse_known_args()


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Process:
    def __init__(self, command, log):
        self.path = log
        self.output = log.open("w", encoding="utf-8")
        self.process = subprocess.Popen(command, stdout=self.output, stderr=self.output)

    def log(self):
        return self.path.read_text(encoding="utf-8", errors="replace")

    def wait_log(self, value, count=1):
        deadline = time.monotonic() + 7
        while self.log().count(value) < count:
            if self.process.poll() is not None or time.monotonic() > deadline:
                raise AssertionError("missing event " + value + ": " + self.log())
            time.sleep(0.02)

    def stop(self, hard=False):
        if self.process.poll() is None:
            self.process.kill() if hard else self.process.terminate()
        try:
            self.process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
            raise AssertionError("process failed to stop")
        self.output.close()


class ProxyHarness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path.cwd().resolve() / ("proxy-fixtures-" + uuid.uuid4().hex)
        cls.addClassCleanup(cls.cleanup_files)
        spec = importlib.util.spec_from_file_location("shadow_pki", Path(ARGS.source) / "scripts/dev-certificates.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.generate(cls.root, ARGS.openssl, test_fixtures=True)
        cls.api = Backend("api")
        cls.addClassCleanup(cls.api.stop)
        cls.website = Backend("website")
        cls.addClassCleanup(cls.website.stop)

    @classmethod
    def cleanup_files(cls):
        if cls.root.parent != Path.cwd().resolve() or not cls.root.name.startswith("proxy-fixtures-"):
            raise RuntimeError("unsafe fixture directory")
        if cls.root.exists():
            shutil.rmtree(cls.root)

    def setUp(self):
        self.working = self.root / uuid.uuid4().hex
        self.working.mkdir()
        self.children = []
        self.counter = 0
        self.addCleanup(self.cleanup_children)
        self.wss_port, self.http_port = port(), port()
        while self.wss_port == self.http_port:
            self.http_port = port()

    def cleanup_children(self):
        for child in reversed(self.children):
            child.stop()

    def fingerprint(self, profile):
        der = ssl.PEM_cert_to_DER_cert((self.root / (profile + ".crt")).read_text(encoding="ascii"))
        return hashlib.sha256(der).hexdigest()

    def credentials(self, profile="agent", indent="", mutual=True):
        path = lambda name: json.dumps((self.root / name).as_posix())
        text = indent + "security:\n"
        if mutual:
            text += indent + "  ca_file: " + path("ca.crt") + "\n"
        text += indent + "  certificate_file: " + path(profile + ".crt") + "\n"
        text += indent + "  private_key_file: " + path(profile + ".key") + "\n"
        return text

    def write(self, text):
        self.counter += 1
        target = self.working / f"config-{self.counter}.yaml"
        target.write_text(text, encoding="utf-8")
        return target

    def agent_config(self, selected=None, profile="agent", name="home-server", maximum=16, timeout=1200, reconnect=False, budget=67108864, write_timeout=10000):
        if selected is None:
            selected = [("api", "api.example.test", self.api.server_port), ("website", "app.example.test", self.website.server_port)]
        text = (f"transport: wss\nagent:\n  name: {name}\n  gateway_host: 127.0.0.1\n  port: {self.wss_port}\n"
                f"  timeout_ms: 2000\n  max_in_flight: {maximum}\n  backend_timeout_ms: {timeout}\n"
                f"  buffer_budget_bytes: {budget}\n  write_timeout_ms: {write_timeout}\n"
                f"  reconnect:\n    enabled: {str(reconnect).lower()}\n    initial_ms: 100\n    max_ms: 400\n")
        text += self.credentials(profile) + "services:\n"
        if not selected:
            text = text.removesuffix("services:\n") + "services: []\n"
        for service, host, local_port in selected:
            text += f"  - {{name: {service}, hostname: {host}, local_host: 127.0.0.1, local_port: {local_port}}}\n"
        return self.write(text)

    def gateway_config(self, policies=None, timeout=1800, maximum=16, connections=64, rate=100, budget=67108864, tunnel_budget=134217728, write_timeout=10000):
        if policies is None:
            policies = [("home-server", "agent", [("api", "api.example.test"), ("website", "app.example.test")])]
        text = (f"transport: wss\ngateway:\n  bind_host: 127.0.0.1\n  port: {self.wss_port}\n  timeout_ms: 2000\n"
                "  max_connections: 16\n  heartbeat_interval_ms: 200\n  heartbeat_timeout_ms: 2000\n"
                f"  tunnel_buffer_budget_bytes: {tunnel_budget}\n  write_timeout_ms: {write_timeout}\n")
        text += self.credentials("gateway") + "authorized_agents:\n"
        for name, profile, entries in policies:
            text += f"  - name: {name}\n    certificate_sha256: {self.fingerprint(profile)}\n    services:\n"
            for service, host in entries:
                text += f"      - {{name: {service}, hostname: {host}}}\n"
        text += (f"http:\n  bind_host: 127.0.0.1\n  port: {self.http_port}\n  max_connections: {connections}\n"
                 f"  max_in_flight: {maximum}\n  requests_per_second: {rate}\n  request_timeout_ms: {timeout}\n")
        text += f"  buffer_budget_bytes: {budget}\n"
        return self.write(text + self.credentials("gateway", indent="  ", mutual=False))

    def launch(self, executable, config):
        self.counter += 1
        child = Process([executable, "--config", str(config)], self.working / f"child-{self.counter}.log")
        self.children.append(child)
        return child

    def gateway(self, **options):
        self.gateway_path = self.gateway_config(**options)
        self.gw = self.launch(ARGS.gateway, self.gateway_path)
        self.gw.wait_log("https_listening")
        self.gw.wait_log("wss_listening")
        return self.gw

    def agent(self, **options):
        self.agent_path = self.agent_config(**options)
        self.ag = self.launch(ARGS.agent, self.agent_path)
        self.ag.wait_log("services_registered")
        return self.ag

    def start(self, gateway=None, agent=None):
        self.gateway(**(gateway or {}))
        self.agent(**(agent or {}))

    def context(self):
        context = ssl.create_default_context(cafile=str(self.root / "ca.crt"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        return context

    def call(self, method="GET", target="/echo", body=None, host="api.example.test", headers=None, chunked=False):
        connection = http.client.HTTPSConnection("127.0.0.1", self.http_port, context=self.context(), timeout=5)
        try:
            fields = {"Host": host, **(headers or {})}
            connection.request(method, target, body, fields, encode_chunked=chunked)
            response = connection.getresponse()
            return response.status, response.reason, response.getheaders(), response.read()
        finally:
            connection.close()

    def raw(self, request, method="GET", hostname="127.0.0.1"):
        with socket.create_connection(("127.0.0.1", self.http_port), timeout=4) as raw:
            with self.context().wrap_socket(raw, server_hostname=hostname) as sock:
                self.assertEqual(sock.version(), "TLSv1.3")
                sock.sendall(request)
                response = http.client.HTTPResponse(sock, method=method)
                response.begin()
                return response.status, response.reason, response.getheaders(), response.read()

    @staticmethod
    def fields(headers):
        return {key.lower(): value for key, value in headers}

class ReverseProxy(ProxyHarness):
    def test_two_services_route_by_hostname_over_verified_https(self):
        self.start()
        for host, expected in (("api.example.test", "api"), ("app.example.test", "website"), ("API.Example.Test:8443", "api")):
            status, _, headers, body = self.call(host=host)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["service"], expected)
            self.assertEqual(self.fields(headers)["x-service"], expected)
        result = self.raw(b"GET /fixed HTTP/1.1\r\nHost: api.example.test\r\n\r\n", hostname="api.example.test")
        self.assertEqual(result[3], b"hello-api")

    def test_methods_headers_query_and_binary_request_bodies(self):
        self.start()
        payload = b"a\x00\xffb\r\ncontent"
        for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            with self.subTest(method=method):
                status, _, _, result = self.call(method, "/echo?q=a%20b", payload, headers={"X-Correlation": method, "Authorization": "Bearer fixture", "Cookie": "session=fixture"})
                self.assertEqual(status, 200)
                response = json.loads(result)
                self.assertEqual(response["method"], method)
                self.assertEqual(response["path"], "/echo?q=a%20b")
                self.assertEqual(base64.b64decode(response["body"]), payload)
                headers = self.fields(response["headers"])
                self.assertEqual(headers["x-correlation"], method)
                self.assertEqual(headers["authorization"], "Bearer fixture")
                self.assertEqual(headers["cookie"], "session=fixture")

    def test_binary_response_gzip_status_and_duplicate_cookies(self):
        self.start()
        result = self.call(target="/binary")
        self.assertEqual(result[3], bytes(range(256)))
        result = self.call(target="/gzip")
        self.assertEqual(self.fields(result[2])["content-encoding"], "gzip")
        self.assertEqual(gzip.decompress(result[3]), bytes(range(256)))
        result = self.call(target="/cookies")
        self.assertEqual(result[:2], (201, "Created Here"))
        self.assertEqual([value for key, value in result[2] if key.lower() == "set-cookie"], ["a=1; HttpOnly", "b=2; Secure"])
        for status in (204, 304, 404, 418, 503):
            result = self.call(target=f"/status/{status}")
            self.assertEqual(result[0], status)
            if status in (204, 304):
                self.assertEqual(result[3], b"")
        self.assertEqual(self.call(target="/interim")[0], 200)

    def test_head_preserves_representation_length_and_sends_no_body(self):
        self.start()
        result = self.call("HEAD", "/fixed")
        self.assertEqual(result[0], 200)
        self.assertEqual(result[3], b"")
        self.assertEqual(self.fields(result[2])["content-length"], str(len(b"hello-api")))
        result = self.call("HEAD", "/fixed", host="unpublished.example.test")
        self.assertEqual(result[0], 404)
        self.assertEqual(result[3], b"")

    def test_head_errors_do_not_disconnect_other_services_or_pending_requests(self):
        self.start(agent={"timeout": 400, "maximum": 1})
        result = self.call("HEAD", "/fixed?delay=1000")
        self.assertEqual(result[0], 504)
        self.assertEqual(result[3], b"")
        self.assertEqual(self.call(target="/fixed", host="app.example.test")[3], b"hello-website")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            before = self.api.count()
            pending = pool.submit(self.call, target="/fixed?delay=200")
            deadline = time.monotonic() + 3
            while self.api.count() == before and time.monotonic() < deadline:
                time.sleep(0.005)
            result = self.call("HEAD", "/fixed")
            self.assertEqual(result[0], 503)
            self.assertEqual(result[3], b"")
            self.assertEqual(pending.result()[0], 200)
        self.assertIsNone(self.ag.process.poll())
        self.assertEqual(self.ag.log().count("services_registered"), 1)

    def test_chunked_request_and_response_are_reframed_without_hop_headers(self):
        self.start()
        result = self.call("POST", "/echo", iter([b"abc", b"\0xyz"]), chunked=True)
        self.assertEqual(result[0], 200)
        echoed = json.loads(result[3])
        self.assertEqual(base64.b64decode(echoed["body"]), b"abc\0xyz")
        self.assertNotIn("transfer-encoding", self.fields(echoed["headers"]))
        result = self.call(target="/chunked")
        self.assertEqual(result[3], b"a\0xyz")
        fields = self.fields(result[2])
        self.assertNotIn("transfer-encoding", fields)
        self.assertNotIn("trailer", fields)
        self.assertNotIn("x-internal", fields)
        self.assertEqual(fields["content-length"], "5")
        result = self.call(target="/eof")
        self.assertEqual(result[3], b"body\0until-eof")
        self.assertEqual(self.fields(result[2])["content-length"], str(len(result[3])))

    def test_spoofed_proxy_and_connection_nominated_headers_do_not_reach_origin(self):
        self.start()
        result = self.call(headers={"Connection": "keep-alive, X-Private", "X-Private": "secret",
                                    "Forwarded": "for=spoof", "X-Forwarded-For": "spoof", "X-Forwarded-Proto": "http", "X-Real-IP": "spoof"})
        fields = self.fields(json.loads(result[3])["headers"])
        self.assertNotIn("x-private", fields)
        self.assertNotIn("forwarded", fields)
        self.assertNotIn("x-real-ip", fields)
        self.assertEqual(fields["x-forwarded-for"], "127.0.0.1")
        self.assertEqual(fields["x-forwarded-proto"], "https")
        self.assertEqual(fields["x-forwarded-host"], "api.example.test")
        self.assertNotIn("x-internal", self.fields(result[2]))
        self.assertEqual(self.fields(result[2])["x-end-to-end"], "preserved")

    def test_concurrent_out_of_order_requests_remain_isolated_across_services(self):
        self.start()
        def invoke(index):
            host = "api.example.test" if index % 2 == 0 else "app.example.test"
            path = f"/echo?id={index}&delay={(15 - index) * 8}"
            body = f"payload-{index}".encode()
            result = self.call("POST", path, body, host=host)
            self.assertEqual(result[0], 200, result)
            response = json.loads(result[3])
            self.assertEqual(response["path"], path)
            self.assertEqual(base64.b64decode(response["body"]), body)
            self.assertEqual(response["service"], "api" if index % 2 == 0 else "website")
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(invoke, range(16)))

    def test_unknown_hosts_and_proxy_targets_never_select_internal_destinations(self):
        self.start()
        before = self.api.count() + self.website.count()
        self.assertEqual(self.call(host="unknown.example.test")[0], 404)
        self.assertEqual(self.call(host="127.0.0.1:8080")[0], 404)
        self.assertEqual(self.call(target="http://169.254.169.254/latest/")[0], 400)
        self.assertEqual(self.call("CONNECT", "127.0.0.1:22")[0], 405)
        self.assertEqual(self.call("TRACE", "/")[0], 405)
        self.assertEqual(self.call(headers={"Via": "1.1 shadownet"})[0], 508)
        self.assertEqual(before, self.api.count() + self.website.count())

    def test_options_max_forwards_is_handled_by_the_intermediary(self):
        self.start()
        before = self.api.count()
        result = self.call("OPTIONS", "*", headers={"Max-Forwards": "0"})
        self.assertEqual(result[0], 200)
        self.assertIn("GET", self.fields(result[2])["allow"])
        self.assertEqual(self.api.count(), before)
        result = self.call("OPTIONS", "/echo", headers={"Max-Forwards": "1"})
        self.assertEqual(self.fields(json.loads(result[3])["headers"])["max-forwards"], "0")

    def test_unregistered_authorized_service_returns_503(self):
        self.start(agent={"selected": [("api", "api.example.test", self.api.server_port)]})
        self.assertEqual(self.call()[0], 200)
        self.assertEqual(self.call(host="app.example.test")[0], 503)

    def test_registration_is_atomic_and_cannot_claim_an_unapproved_hostname(self):
        self.gateway()
        selected = [("api", "api.example.test", self.api.server_port), ("evil", "evil.example.test", self.website.server_port)]
        agent = self.launch(ARGS.agent, self.agent_config(selected=selected))
        self.assertEqual(agent.process.wait(timeout=5), 1)
        self.assertNotIn("services_registered", self.gw.log())
        self.assertEqual(self.call()[0], 503)
        self.assertEqual(self.call(host="evil.example.test")[0], 404)

    def test_limits_reject_oversized_requests_and_bad_upstream_responses(self):
        self.start()
        prefix = b"POST /binary HTTP/1.1\r\nHost: api.example.test\r\n"
        self.assertEqual(self.raw(prefix + b"Content-Length: 1048577\r\n\r\n")[0], 413)
        self.assertEqual(self.raw(prefix + b"Transfer-Encoding: chunked\r\n\r\n100001\r\n")[0], 413)
        self.assertEqual(self.raw(b"GET / HTTP/1.1\r\nHost: api.example.test\r\nX-Huge: " + b"x" * 17000 + b"\r\n\r\n")[0], 431)
        for path in ("/malformed", "/ambiguous", "/oversize", "/huge-header", "/transfer-gzip"):
            self.assertEqual(self.call(target=path)[0], 502, path)
        body = bytes(range(256)) * 4096
        result = self.call("POST", "/binary", body)
        self.assertEqual(result[0], 200)
        self.assertEqual(result[3], body)

    def test_malformed_http_and_ambiguous_framing_are_rejected(self):
        self.start()
        cases = [b"GET / HTTP/1.1\r\n\r\n", b"GET / HTTP/1.1\r\nHost: api.example.test\r\nHost: app.example.test\r\n\r\n",
                 b"POST / HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                 b"POST / HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na",
                 b"GET / HTTP/1.1\r\nHost: api.example.test\r\nConnection: Host\r\n\r\n",
                 b"POST /binary HTTP/1.1\r\nHost: api.example.test\r\nTransfer-Encoding: gzip, chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
                 b"GET / HTTP/1.1\r\nHost: api.example.test\r\nInvalid Header: value\r\n\r\n"]
        before = self.api.count()
        for request in cases:
            self.assertEqual(self.raw(request)[0], 400, request)
        self.assertEqual(self.raw(b"GET / HTTP/1.0\r\nHost: api.example.test\r\n\r\n")[0], 505)
        self.assertEqual(before, self.api.count())

    def test_expect_continue_is_serviced_before_the_client_sends_its_body(self):
        self.start()
        with socket.create_connection(("127.0.0.1", self.http_port), timeout=4) as raw, self.context().wrap_socket(raw, server_hostname="127.0.0.1") as sock:
            sock.sendall(b"POST /binary HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n")
            interim = b""
            while not interim.endswith(b"\r\n\r\n"):
                interim += sock.recv(1)
            self.assertIn(b"100 Continue", interim)
            sock.sendall(b"a\0b")
            response = http.client.HTTPResponse(sock)
            response.begin()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"a\0b")
        result = self.raw(b"POST / HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 0\r\nExpect: unsupported\r\n\r\n")
        self.assertEqual(result[0], 417)

    def test_gateway_timeout_cancels_origin_work_and_frees_the_agent_slot(self):
        self.start(gateway={"timeout": 200}, agent={"maximum": 1, "timeout": 1500})
        self.assertEqual(self.call(target="/echo?delay=700")[0], 504)
        self.assertEqual(self.call(target="/fixed")[3], b"hello-api")

    def test_origin_timeout_and_connection_failure_are_explicit(self):
        self.start(agent={"timeout": 150})
        self.assertEqual(self.call(target="/echo?delay=500")[0], 504)
        self.ag.stop(hard=True)
        self.gw.wait_log("tunnel_disconnected")
        # Use an accepted connection that closes before responding. OS-level
        # connection-refused delays differ and may legitimately reach the deadline.
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(4)
            def reset():
                with listener.accept()[0] as peer:
                    peer.settimeout(3)
                    peer.recv(4096)
            worker = threading.Thread(target=reset, daemon=True)
            worker.start()
            self.agent(selected=[("api", "api.example.test", listener.getsockname()[1])])
            self.assertEqual(self.call()[0], 502)
            worker.join(timeout=4)
            self.assertFalse(worker.is_alive())

    def test_https_connection_cap_and_idle_handshake_timeout_release_resources(self):
        self.start(gateway={"connections": 1, "timeout": 250})
        with socket.create_connection(("127.0.0.1", self.http_port), timeout=3) as held:
            time.sleep(0.05)
            with self.assertRaises((ssl.SSLError, ConnectionError, EOFError)):
                self.call()
            self.assertEqual(held.recv(1), b"")
        self.assertEqual(self.call()[0], 200)

    def test_inflight_limit_returns_503_and_then_recovers(self):
        self.start(gateway={"maximum": 1})
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            before = self.api.count()
            first = pool.submit(self.call, target="/echo?delay=350")
            deadline = time.monotonic() + 3
            while self.api.count() == before and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(self.call()[0], 503)
            self.assertEqual(first.result()[0], 200)
        self.assertEqual(self.call()[0], 200)

    def test_global_rate_limit_recovers(self):
        self.start(gateway={"rate": 1})
        self.assertEqual(self.call()[0], 200)
        self.assertEqual(self.call()[0], 429)
        time.sleep(1.05)
        self.assertEqual(self.call()[0], 200)

    def test_tunnel_loss_fails_pending_requests_without_replay_and_routes_recover(self):
        self.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            before = self.api.count()
            pending = pool.submit(self.call, "POST", "/echo?delay=700", b"do-not-replay")
            deadline = time.monotonic() + 3
            while self.api.count() == before and time.monotonic() < deadline:
                time.sleep(0.01)
            self.ag.stop(hard=True)
            self.assertEqual(pending.result()[0], 503)
        self.assertEqual(self.call()[0], 503)
        self.agent()
        self.assertEqual(self.call(target="/fixed")[3], b"hello-api")
        with self.api.lock:
            self.assertEqual(sum(body == b"do-not-replay" for _, _, body in self.api.records), 1)

    def test_services_register_again_after_gateway_restart(self):
        self.start(agent={"reconnect": True})
        self.assertEqual(self.call()[0], 200)
        self.gw.stop(hard=True)
        self.ag.wait_log("reconnect_scheduled")
        self.gw = self.launch(ARGS.gateway, self.gateway_path)
        self.gw.wait_log("https_listening")
        self.ag.wait_log("services_registered", count=2)
        self.assertEqual(self.call(target="/fixed")[3], b"hello-api")
        self.assertEqual(self.call(target="/fixed", host="app.example.test")[3], b"hello-website")

    def test_one_agent_cannot_complete_another_agents_request(self):
        policies = [("home-server", "agent", [("api", "api.example.test")]),
                    ("second-agent", "other-agent", [("website", "app.example.test")])]
        self.gateway(policies=policies)
        first = Peer.connect(self.root, self.wss_port)
        second = Peer.connect(self.root, self.wss_port, "other-agent", "second-agent")
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        first.send(6, services([("api", "api.example.test")]))
        second.send(6, services([("website", "app.example.test")]))
        self.assertEqual(first.data()[0], 7)
        self.assertEqual(second.data()[0], 7)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a = pool.submit(self.call)
            b = pool.submit(self.call, host="app.example.test")
            type_a, packet_a = first.data()
            type_b, packet_b = second.data()
            self.assertEqual((type_a, type_b), (8, 8))
            id_a, id_b = struct.unpack("!Q", packet_a[:8])[0], struct.unpack("!Q", packet_b[:8])[0]
            self.assertNotEqual(id_a, id_b)
            first.send(9, wire_response(id_b, b"forged"))
            self.assertEqual(a.result()[0], 503)
            second.send(9, wire_response(id_b, b"correct-website"))
            self.assertEqual(b.result()[3], b"correct-website")

    def test_late_response_cannot_satisfy_a_new_request(self):
        self.gateway(timeout=180)
        peer = Peer.connect(self.root, self.wss_port)
        self.addCleanup(peer.close)
        peer.send(6, services([("api", "api.example.test")]))
        self.assertEqual(peer.data()[0], 7)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            old = pool.submit(self.call)
            kind, payload = peer.data()
            self.assertEqual(kind, 8)
            old_id = struct.unpack("!Q", payload[:8])[0]
            self.assertEqual(old.result()[0], 504)
            self.assertEqual(peer.data()[0], 10)
            current = pool.submit(self.call)
            kind, payload = peer.data()
            self.assertEqual(kind, 8)
            current_id = struct.unpack("!Q", payload[:8])[0]
            self.assertNotEqual(old_id, current_id)
            peer.send(9, wire_response(old_id, b"stale"))
            peer.send(9, wire_response(current_id, b"current"))
            self.assertEqual(current.result()[3], b"current")

    def test_agent_allowlist_rejects_arbitrary_service_and_host_from_gateway(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.root / "ca.crt")
        context.load_cert_chain(self.root / "gateway.crt", self.root / "gateway.key")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", self.wss_port))
            listener.listen(1)
            listener.settimeout(4)
            agent = self.launch(ARGS.agent, self.agent_config())
            with listener.accept()[0] as raw, context.wrap_socket(raw, server_side=True) as sock:
                peer = Peer.accept(sock)
                kind, registered = peer.data()
                self.assertEqual(kind, 6)
                peer.send(7, registered)
                before = self.api.count() + self.website.count()
                for identifier, service, host, expected in ((1, "not-allowed", "api.example.test", 404),
                                                            (2, "api", "app.example.test", 403)):
                    peer.send(8, wire_request(identifier, service, host))
                    kind, response = peer.data()
                    self.assertEqual(kind, 9)
                    self.assertEqual(struct.unpack("!QH", response[:10]), (identifier, expected))
                self.assertEqual(before, self.api.count() + self.website.count())
                peer.send(8, wire_request(3, "api", "api.example.test"))
                kind, response = peer.data()
                self.assertEqual(kind, 9)
                self.assertEqual(struct.unpack("!QH", response[:10]), (3, 200))
                peer.send(8, wire_request(4, "api", "api.example.test", target="http://169.254.169.254/"))
                self.assertEqual(agent.process.wait(timeout=4), 1)

    def test_invalid_public_policy_and_limits_fail_offline(self):
        path = self.gateway_config()
        good = path.read_text()
        cases = [good.replace("port: " + str(self.http_port), "port: " + str(self.wss_port)),
                 good.replace("max_in_flight: 16", "max_in_flight: 0"),
                 good.replace("requests_per_second: 100", "requests_per_second: 0"),
                 good.replace("hostname: app.example.test", "hostname: api.example.test"),
                 good.replace("    certificate_file:", "    verify: false\n    certificate_file:"),
                 good.replace("gateway.key", "agent.key")]
        for text in cases:
            result = subprocess.run([ARGS.cli, "config", "validate", "--type", "gateway", "--config", str(self.write(text))],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + TEST_ARGS, verbosity=2)
