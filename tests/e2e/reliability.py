"""Bounded buffers, slow readers, queue recovery and sustained traffic with faults."""
import concurrent.futures
from contextlib import contextmanager
import http.client
import json
import re
import socket
import ssl
import statistics
import struct
import sys
import threading
import time
import unittest
from reverse_proxy import ProxyHarness, ARGS, TEST_ARGS
from tunnel_peer import Peer, header, request as wire_request


class Reliability(ProxyHarness):
    @contextmanager
    def client(self):
        with socket.create_connection(("127.0.0.1", self.http_port), timeout=4) as raw:
            with self.context().wrap_socket(raw, server_hostname="127.0.0.1") as sock:
                yield sock

    @staticmethod
    def upload_header(sock):
        sock.sendall(b"POST /binary HTTP/1.1\r\nHost: api.example.test\r\n"
                     b"Content-Length: 262144\r\nExpect: 100-continue\r\n\r\n")

    def finish_upload(self, sock, marker):
        body = marker * 262144
        sock.sendall(body)
        response = http.client.HTTPResponse(sock)
        response.begin()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), body)
        response.close()

    def test_global_http_budget_waits_before_continue_and_resumes_in_fifo_order(self):
        self.start(gateway={"budget": 8388608, "timeout": 3000})
        with self.client() as first, self.client() as second, self.client() as third:
            self.upload_header(first)
            self.assertIn(b"100 Continue", header(first))
            self.upload_header(second)
            self.gw.wait_log("http_buffer_wait")
            self.upload_header(third)
            self.gw.wait_log("http_buffer_wait", count=2)
            # These sockets have headers but neither a body nor permission to send it.
            for sock in (second, third):
                sock.settimeout(0.1)
                with self.assertRaises(TimeoutError):
                    sock.recv(1)
                sock.settimeout(4)
            self.finish_upload(first, b"a")
            first.close()
            self.assertIn(b"100 Continue", header(second))
            self.finish_upload(second, b"b")
            second.close()
            self.assertIn(b"100 Continue", header(third))
            self.finish_upload(third, b"c")
        self.assertEqual(self.call(target="/fixed")[0], 200)
        self.assertEqual(self.ag.log().count("services_registered"), 1)

    def test_abandoned_upload_and_expired_waiters_release_admission(self):
        self.start(gateway={"budget": 8388608, "timeout": 400})
        before = self.api.count()
        with self.client() as blocked, self.client() as abandoned:
            self.upload_header(blocked)
            self.assertIn(b"100 Continue", header(blocked))
            self.upload_header(abandoned)
            self.gw.wait_log("http_buffer_wait")
            abandoned.close()
            time.sleep(0.6)
        self.assertEqual(self.api.count(), before)
        self.assertEqual(self.call(target="/fixed")[3], b"hello-api")

    def test_agent_buffer_admission_rejects_excess_work_and_recovers(self):
        self.start(agent={"budget": 8388608})
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            before = self.api.count()
            pending = pool.submit(self.call, target="/fixed?delay=500")
            deadline = time.monotonic() + 3
            while self.api.count() == before and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual(self.call(host="app.example.test")[0], 503)
            self.assertEqual(pending.result()[0], 200)
        self.assertEqual(self.call(host="app.example.test", target="/fixed")[3], b"hello-website")
        self.assertEqual(self.ag.log().count("services_registered"), 1)

    def test_slow_public_reader_holds_its_budget_until_response_is_released(self):
        self.start(gateway={"budget": 8388608, "timeout": 4000})
        with socket.socket() as raw:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            raw.settimeout(4)
            raw.connect(("127.0.0.1", self.http_port))
            with self.context().wrap_socket(raw, server_hostname="127.0.0.1") as slow, self.client() as waiting:
                before = self.api.count()
                slow.sendall(b"GET /large?id=public HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
                deadline = time.monotonic() + 2
                while self.api.count() == before and time.monotonic() < deadline:
                    time.sleep(0.005)
                waiting.sendall(b"GET /fixed HTTP/1.1\r\nHost: app.example.test\r\n\r\n")
                self.gw.wait_log("http_buffer_wait")
                waiting.settimeout(0.1)
                with self.assertRaises(TimeoutError):
                    waiting.recv(1)
                waiting.settimeout(4)
                response = http.client.HTTPResponse(slow)
                response.begin()
                self.assertEqual(response.status, 200)
                self.assertEqual(len(response.read()), 1048576)
                response.close()
                slow.close()
                response = http.client.HTTPResponse(waiting)
                response.begin()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b"hello-website")
                response.close()

    def test_global_tunnel_buffer_budget_is_enforced_before_tls_and_reusable(self):
        self.gateway(tunnel_budget=16777216)
        first = Peer.connect(self.root, self.wss_port)
        self.addCleanup(first.close)
        with socket.create_connection(("127.0.0.1", self.wss_port), timeout=3) as second:
            self.gw.wait_log("tunnel_buffer_limit")
            self.assertEqual(second.recv(1), b"")
        first.close()
        self.gw.wait_log("tunnel_disconnected")
        self.agent()
        self.assertEqual(self.call(target="/fixed")[0], 200)

    @contextmanager
    def slow_gateway(self, write_timeout=5000):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.root / "ca.crt")
        context.load_cert_chain(self.root / "gateway.crt", self.root / "gateway.key")
        with socket.socket() as listener:
            # Bound the peer's advertised receive window before the handshake.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
            listener.bind(("127.0.0.1", self.wss_port))
            listener.listen(1)
            listener.settimeout(5)
            agent = self.launch(ARGS.agent, self.agent_config(maximum=16, timeout=3000, write_timeout=write_timeout))
            with listener.accept()[0] as raw, context.wrap_socket(raw, server_side=True) as sock:
                sock.settimeout(5)
                peer = Peer.accept(sock)
                kind, registration = peer.data()
                self.assertEqual(kind, 6)
                peer.send(7, registration)
                yield peer, agent

    def test_slow_tunnel_defers_responses_cancels_pending_reply_and_resumes(self):
        with self.slow_gateway() as (peer, agent):
            for identifier in range(1, 13):
                peer.send(8, wire_request(identifier, "api", "api.example.test", target=f"/large?id={identifier}"))
            agent.wait_log("response_backpressure")
            cancelled = int(re.search(r"response_backpressure id=(\d+)", agent.log())[1])
            peer.send(10, struct.pack("!Q", cancelled))
            agent.wait_log(f"response_cancelled id={cancelled}")
            received = set()
            for _ in range(11):
                kind, payload = peer.data()
                self.assertEqual(kind, 9)
                identifier, status = struct.unpack("!QH", payload[:10])
                self.assertEqual(status, 200)
                self.assertNotIn(identifier, received)
                self.assertNotEqual(identifier, cancelled)
                self.assertIn(f"/large?id={identifier}:api:".encode(), payload)
                received.add(identifier)
            self.assertEqual(received, set(range(1, 13)) - {cancelled})
            agent.wait_log("response_resumed")
            self.assertIsNone(agent.process.poll())
            self.assertEqual(agent.log().count("tunnel_established"), 1)

    def test_nonreading_tunnel_hits_write_deadline(self):
        with self.slow_gateway(write_timeout=250) as (peer, agent):
            for identifier in range(1, 13):
                peer.send(8, wire_request(identifier, "api", "api.example.test", target=f"/large?id={identifier}"))
            self.assertEqual(agent.process.wait(timeout=5), 1)
            self.assertIn("tunnel_write_timeout", agent.log())

    def test_resource_configuration_is_validated_offline(self):
        for kind, path, fields in (
            ("agent", self.agent_config(), ("buffer_budget_bytes: 67108864", "write_timeout_ms: 10000")),
            ("gateway", self.gateway_config(), ("buffer_budget_bytes: 67108864", "tunnel_buffer_budget_bytes: 134217728", "write_timeout_ms: 10000"))):
            import subprocess
            for field in fields:
                for invalid in ("0", "-1", "99999999999999999999999", "wrong"):
                    replacement = field.split(":", 1)[0] + ": " + invalid
                    config = self.write(path.read_text().replace(field, replacement))
                    result = subprocess.run([ARGS.cli, "config", "validate", "--type", kind, "--config", str(config)],
                                            capture_output=True, text=True, timeout=3)
                    self.assertEqual(result.returncode, 1, field + "=" + invalid)

    def test_sustained_traffic_with_two_gateway_restarts_and_no_post_replay(self):
        duration, workers = ARGS.load_seconds, ARGS.load_workers
        self.assertTrue(4 <= duration <= 300 and 4 <= workers <= 32, "load duration must be 4..300s, workers 4..32")
        ARGS.load_report.unlink(missing_ok=True)
        self.start(gateway={"rate": 10000, "maximum": 64}, agent={"reconnect": True, "maximum": 64})
        lock = threading.Lock()
        active_fault = threading.Event()
        state = {"epoch": 0, "success": 0, "fault_errors": 0, "failures": [], "latencies": [], "hosts": set()}
        deadline = time.monotonic() + duration
        started = time.monotonic()

        def worker(number):
            sequence = 0
            while time.monotonic() < deadline:
                sequence += 1
                host = "api.example.test" if (number + sequence) % 2 else "app.example.test"
                path = f"/binary?load={self.working.name}-{number}-{sequence}"
                body = (f"{number}:{sequence}:".encode() + bytes(range(256))) * 16
                with lock:
                    epoch, fault = state["epoch"], active_fault.is_set()
                tick = time.monotonic()
                error = None
                try:
                    status, _, headers, actual = self.call("POST", path, body, host=host)
                    if status != 200:
                        if status not in (503, 504):
                            with lock:
                                state["failures"].append(f"unexpected HTTP {status}")
                            continue
                        error = f"HTTP {status}"
                    elif actual != body or self.fields(headers).get("x-service") != ("api" if host.startswith("api") else "website"):
                        with lock:
                            state["failures"].append("corrupted or misrouted response")
                        continue
                except ssl.SSLCertVerificationError:
                    with lock:
                        state["failures"].append("TLS identity validation failed")
                    continue
                except (OSError, http.client.HTTPException) as failure:
                    error = type(failure).__name__
                with lock:
                    if error:
                        if fault or active_fault.is_set() or epoch != state["epoch"]:
                            state["fault_errors"] += 1
                        else:
                            state["failures"].append(error)
                    else:
                        state["success"] += 1
                        state["hosts"].add(host)
                        state["latencies"].append((time.monotonic() - tick) * 1000)

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            tasks = [pool.submit(worker, index) for index in range(workers)]
            for _ in range(2):
                time.sleep(duration / 4)
                with lock:
                    state["epoch"] += 1
                    active_fault.set()
                self.gw.stop(hard=True)
                self.gw = self.launch(ARGS.gateway, self.gateway_path)
                self.gw.wait_log("https_listening")
                self.ag.wait_log("services_registered", count=state["epoch"] + 1)
                active_fault.clear()
            for task in tasks:
                task.result(timeout=max(10, deadline - time.monotonic() + 10))
        elapsed = time.monotonic() - started
        self.assertFalse(state["failures"], state["failures"][:8])
        self.assertGreaterEqual(state["success"], workers * 2)
        self.assertEqual(len(state["hosts"]), 2)
        self.assertGreater(state["fault_errors"], 0)
        for host, marker in (("api.example.test", b"hello-api"), ("app.example.test", b"hello-website")):
            self.assertEqual(self.call(target="/fixed", host=host)[3], marker)
        records = [entry[1] for backend in (self.api, self.website) for entry in backend.records
                   if "load=" + self.working.name in entry[1]]
        self.assertEqual(len(records), len(set(records)), "POST reached an origin more than once")
        latencies = sorted(state["latencies"])
        report = {"duration_seconds": round(elapsed, 3), "workers": workers, "successful_requests": state["success"],
                  "expected_errors_during_faults": state["fault_errors"], "unexpected_errors": state["failures"],
                  "gateway_restarts": 2, "origin_requests": len(records), "duplicate_origin_requests": 0,
                  "latency_ms_p50": round(statistics.median(latencies), 3),
                  "latency_ms_p95": round(latencies[int((len(latencies) - 1) * .95)], 3)}
        ARGS.load_report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("Load report: " + json.dumps(report), flush=True)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + TEST_ARGS, verbosity=2)
