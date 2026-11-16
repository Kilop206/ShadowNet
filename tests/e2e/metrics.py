"""Real process metrics: lifecycle, privacy, bounded exporter and Prometheus text."""
import concurrent.futures
import http.client
import math
import socket
import subprocess
import sys
import time
import unittest
from reverse_proxy import ProxyHarness, ARGS, TEST_ARGS, port
from tunnel_peer import Peer


class Observability(ProxyHarness):
    def setUp(self):
        super().setUp()
        used = {self.wss_port, self.http_port, self.api.server_port, self.website.server_port}
        def allocate():
            value = port()
            while value in used:
                value = port()
            used.add(value)
            return value
        self.gateway_metrics_port, self.agent_metrics_port = allocate(), allocate()

    def enabled(self, path, value, maximum=4, timeout=2000):
        return self.write(path.read_text() + f"metrics:\n  bind_host: 127.0.0.1\n  port: {value}\n  max_connections: {maximum}\n  timeout_ms: {timeout}\n")

    def start_metrics(self, reconnect=False, gateway=None, agent=None, exporter=None):
        self.gateway_path = self.enabled(self.gateway_config(**(gateway or {})), self.gateway_metrics_port, **(exporter or {}))
        self.gw = self.launch(ARGS.gateway, self.gateway_path)
        self.gw.wait_log("metrics_listening")
        self.gw.wait_log("wss_listening")
        self.agent_path = self.enabled(self.agent_config(reconnect=reconnect, **(agent or {})), self.agent_metrics_port)
        self.ag = self.launch(ARGS.agent, self.agent_path)
        self.ag.wait_log("services_registered")

    def scrape(self, agent=False, method="GET", target="/metrics", headers=None):
        value = self.agent_metrics_port if agent else self.gateway_metrics_port
        connection = http.client.HTTPConnection("127.0.0.1", value, timeout=3)
        try:
            connection.request(method, target, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read().decode("ascii")
        finally:
            connection.close()

    def samples(self, agent=False):
        status, headers, text = self.scrape(agent)
        self.assertEqual(status, 200)
        self.assertIn("version=0.0.4", headers["Content-Type"])
        self.assertTrue(text.endswith("\n"))
        result = {}
        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue
            key, value = line.rsplit(" ", 1)
            self.assertNotIn(key, result)
            number = float(value)
            self.assertTrue(math.isfinite(number) and number >= 0, line)
            result[key] = number
        return result

    def eventually(self, predicate, agent=False):
        deadline = time.monotonic() + 4
        while True:
            values = self.samples(agent)
            if predicate(values):
                return values
            if time.monotonic() > deadline:
                self.fail("metrics did not converge: " + str(values))
            time.sleep(0.02)

    def test_counters_body_bytes_privacy_and_scrapes_do_not_count_as_application_requests(self):
        self.start_metrics()
        baseline = self.samples()
        self.assertEqual(baseline["shadownet_http_requests_total"], 0)
        self.assertEqual(baseline['shadownet_agent_up{agent="home-server"}'], 1)
        self.assertEqual(baseline["shadownet_routes_active"], 2)
        secret = "m6-private-value-do-not-export"
        body = b"a\0binary-body"
        self.assertEqual(self.call("POST", "/binary?secret=" + secret, body, headers={"Authorization": "Bearer " + secret})[3], body)
        self.assertEqual(self.call(host="unknown.example.test")[0], 404)
        self.assertEqual(self.call("HEAD", "/fixed")[0], 200)
        values = self.eventually(lambda m: m["shadownet_http_completed_total"] == 3)
        self.assertEqual(values["shadownet_http_requests_total"], 3)
        self.assertEqual(values['shadownet_http_responses_total{status_class="2xx"}'], 2)
        self.assertEqual(values['shadownet_http_responses_total{status_class="4xx"}'], 1)
        self.assertEqual(values["shadownet_http_request_body_bytes_total"], len(body))
        self.assertEqual(values["shadownet_http_response_body_bytes_total"], len(body) + len(b"Not Found\n"))
        local = self.eventually(lambda m: m["shadownet_http_completed_total"] == 2, agent=True)
        self.assertEqual(local["shadownet_http_response_body_bytes_total"], len(body))
        for role in (False, True):
            status, _, text = self.scrape(role)
            self.assertEqual(status, 200)
            for forbidden in (secret, "api.example.test", "127.0.0.1", self.fingerprint("agent"), "Authorization"):
                self.assertNotIn(forbidden, text)
            if not role:
                ARGS.metrics_snapshot.write_bytes(text.encode("utf-8"))
        self.assertEqual(self.samples()["shadownet_http_requests_total"], 3)

    def test_concurrency_histogram_traffic_and_buffer_gauges_balance(self):
        self.start_metrics(gateway={"maximum": 32}, agent={"maximum": 32})
        body = bytes(range(256))
        def invoke(index):
            return self.call("POST", "/binary?id=" + str(index), body, host="api.example.test" if index % 2 else "app.example.test")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for result in pool.map(invoke, range(24)):
                self.assertEqual(result[0], 200)
                self.assertEqual(result[3], body)
        for role in (False, True):
            values = self.eventually(lambda m: m["shadownet_http_completed_total"] == 24 and m['shadownet_buffer_used_bytes{scope="http"}'] == 0, role)
            self.assertEqual(values["shadownet_http_in_flight"], 0)
            self.assertEqual(values["shadownet_http_aborted_total"], 0)
            self.assertEqual(values["shadownet_http_request_body_bytes_total"], 24 * len(body))
            self.assertEqual(values["shadownet_http_response_body_bytes_total"], 24 * len(body))
            self.assertEqual(values["shadownet_http_request_duration_seconds_count"], 24)
            buckets = [value for key, value in values.items() if key.startswith("shadownet_http_request_duration_seconds_bucket{")]
            self.assertEqual(buckets, sorted(buckets))
            self.assertEqual(values['shadownet_http_request_duration_seconds_bucket{le="+Inf"}'], 24)
            self.assertGreater(values['shadownet_tunnel_bytes_total{direction="sent"}'], 24 * len(body))
            self.assertGreater(values['shadownet_tunnel_bytes_total{direction="received"}'], 24 * len(body))
            self.assertGreater(values['shadownet_buffer_peak_bytes{scope="http"}'], 0)
            self.assertLessEqual(values['shadownet_buffer_peak_bytes{scope="http"}'], values['shadownet_buffer_capacity_bytes{scope="http"}'])

    def test_timeout_and_cancellation_are_observable_without_stuck_inflight(self):
        self.start_metrics(gateway={"timeout": 250}, agent={"timeout": 1200})
        self.assertEqual(self.call(target="/fixed?delay=800")[0], 504)
        values = self.eventually(lambda m: m["shadownet_http_completed_total"] == 1)
        self.assertEqual(values['shadownet_http_responses_total{status_class="5xx"}'], 1)
        self.assertEqual(values["shadownet_http_in_flight"], 0)
        values = self.eventually(lambda m: m["shadownet_http_aborted_total"] == 1, True)
        self.assertEqual(values["shadownet_http_completed_total"], 0)
        self.assertEqual(values["shadownet_http_in_flight"], 0)

    def test_partial_upload_timeout_counts_abort_without_forwarding(self):
        self.start_metrics(gateway={"timeout": 250})
        before = self.api.count()
        with socket.create_connection(("127.0.0.1", self.http_port), timeout=3) as raw:
            with self.context().wrap_socket(raw, server_hostname="127.0.0.1") as sock:
                sock.sendall(b"POST /binary HTTP/1.1\r\nHost: api.example.test\r\nContent-Length: 1000\r\n\r\nx")
                self.eventually(lambda m: m["shadownet_http_in_flight"] == 1)
                values = self.eventually(lambda m: m["shadownet_http_aborted_total"] == 1)
                self.assertEqual(values["shadownet_http_in_flight"], 0)
        self.assertEqual(self.api.count(), before)

    def test_agent_state_routes_and_reconnect_counters_recover(self):
        self.start_metrics(reconnect=True)
        self.gw.stop(hard=True)
        values = self.eventually(lambda m: m['shadownet_agent_up{agent="home-server"}'] == 0 and m['shadownet_events_total{event="reconnect"}'] >= 1, True)
        self.assertEqual(values["shadownet_tunnels_active"], 0)
        self.gw = self.launch(ARGS.gateway, self.gateway_path)
        self.gw.wait_log("metrics_listening")
        self.ag.wait_log("services_registered", count=2)
        values = self.eventually(lambda m: m['shadownet_agent_up{agent="home-server"}'] == 1, True)
        self.assertGreaterEqual(values["shadownet_tunnel_connections_total"], 2)
        self.assertEqual(self.samples()["shadownet_routes_active"], 2)
        self.assertEqual(self.call(target="/fixed")[0], 200)
        self.ag.stop(hard=True)
        values = self.eventually(lambda m: m["shadownet_routes_active"] == 0)
        self.assertEqual(values['shadownet_agent_up{agent="home-server"}'], 0)
        self.assertEqual(values["shadownet_tunnels_active"], 0)

    def test_duplicate_session_cannot_mark_the_real_agent_down(self):
        self.start_metrics()
        with self.assertRaises((EOFError, OSError)):
            Peer.connect(self.root, self.wss_port)
        self.gw.wait_log("duplicate_agent_session")
        values = self.samples()
        self.assertEqual(values['shadownet_agent_up{agent="home-server"}'], 1)
        self.assertEqual(values["shadownet_tunnels_active"], 1)
        self.assertGreaterEqual(values['shadownet_tunnel_closures_total{reason="authentication"}'], 1)
        self.assertEqual(self.call(target="/fixed")[0], 200)

    def test_metrics_endpoint_is_separate_and_rejects_rebinding_origin_and_bad_requests(self):
        self.start_metrics()
        self.assertEqual(self.call(target="/metrics")[0], 200)  # Published API path, never the exporter.
        for method, target, headers, expected in (
                ("GET", "/metrics?secret=private", {}, 404), ("GET", "/", {}, 404), ("POST", "/metrics", {}, 405),
                ("GET", "/metrics", {"Host": "attacker.example"}, 400), ("GET", "/metrics", {"Origin": "http://attacker.example"}, 400),
                ("GET", "/metrics", {"X-Huge": "x" * 5000}, 400)):
            self.assertEqual(self.scrape(method=method, target=target, headers=headers)[0], expected)
        status, headers, body = self.scrape(method="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, "")
        self.assertGreater(int(headers["Content-Length"]), 1000)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.samples()["shadownet_http_requests_total"], 1)

    def test_metrics_connection_cap_and_deadline_release_resources(self):
        self.start_metrics(exporter={"maximum": 1, "timeout": 250})
        with socket.create_connection(("127.0.0.1", self.gateway_metrics_port), timeout=2) as idle:
            with socket.create_connection(("127.0.0.1", self.gateway_metrics_port), timeout=2) as refused:
                self.assertEqual(refused.recv(1), b"")
            self.assertEqual(idle.recv(1), b"")
        self.assertEqual(self.scrape()[0], 200)
        self.assertEqual(self.call(target="/fixed")[0], 200)

    def test_invalid_metrics_config_fails_offline_and_cannot_publish_itself(self):
        for kind, config, value in (("gateway", self.gateway_config(), self.gateway_metrics_port), ("agent", self.agent_config(), self.agent_metrics_port)):
            valid = self.enabled(config, value).read_text()
            cases = [valid.replace("metrics:\n  bind_host: 127.0.0.1", "metrics:\n  bind_host: " + host) for host in ("0.0.0.0", "::", "localhost", "169.254.169.254")]
            cases += [valid.replace("max_connections: 4\n  timeout_ms", "max_connections: 17\n  timeout_ms"), valid.replace("timeout_ms: 2000\n", "timeout_ms: 0\n"), valid + "  unknown: true\n"]
            for collision in ((self.wss_port, self.http_port) if kind == "gateway" else (self.api.server_port, self.website.server_port)):
                cases.append(valid.replace("  port: " + str(value), "  port: " + str(collision)))
            for text in cases:
                result = subprocess.run([ARGS.cli, "config", "validate", "--type", kind, "--config", str(self.write(text))], capture_output=True, text=True, timeout=4)
                self.assertEqual(result.returncode, 1)

    def test_agent_exporter_stops_when_nonreconnecting_agent_fails(self):
        config = self.enabled(self.agent_config(), self.agent_metrics_port)
        process = self.launch(ARGS.agent, config)
        self.assertEqual(process.process.wait(timeout=6), 1)
        with socket.socket() as sock:
            sock.settimeout(1)
            self.assertNotEqual(sock.connect_ex(("127.0.0.1", self.agent_metrics_port)), 0)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + TEST_ARGS, verbosity=2)
