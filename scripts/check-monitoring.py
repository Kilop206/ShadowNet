"""Verify real Prometheus ingestion and an authenticated provisioned Grafana dashboard."""
import argparse
import base64
import json
import math
from pathlib import Path
import time
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--prometheus", default="http://127.0.0.1:9090")
    parser.add_argument("--grafana", default="http://127.0.0.1:3001")
    parser.add_argument("--wait-seconds", type=float, default=30)
    args = parser.parse_args()
    if not 0 <= args.wait_seconds <= 60:
        parser.error("wait-seconds must be 0..60")
    for endpoint in (args.prometheus, args.grafana):
        target = urllib.parse.urlsplit(endpoint)
        if target.scheme != "http" or target.hostname not in ("127.0.0.1", "::1", "localhost") or target.username or target.password or target.query or target.fragment:
            parser.error("monitoring laboratory endpoints must use local HTTP")
    secret = args.password_file.read_text(encoding="ascii").strip()
    if not 16 <= len(secret) <= 256:
        parser.error("invalid laboratory password file")
    authorization = "Basic " + base64.b64encode(("admin:" + secret).encode()).decode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def get(base, path, authenticated=False):
        request = urllib.request.Request(base.rstrip("/") + path)
        if authenticated:
            request.add_header("Authorization", authorization)
        with opener.open(request, timeout=3) as response:
            return json.loads(response.read(1048576))

    def query(expression):
        result = get(args.prometheus, "/api/v1/query?" + urllib.parse.urlencode({"query": expression}))
        if result.get("status") != "success":
            raise RuntimeError("Prometheus query failed")
        return result["data"]["result"]

    deadline = time.monotonic() + args.wait_seconds
    while True:
        try:
            up = query('up{job="shadownet-gateway"}')
            completed = query('shadownet_http_completed_total{job="shadownet-gateway"}')
            count = float(completed[0]["value"][1]) if len(completed) == 1 else 0
            if len(up) != 1 or float(up[0]["value"][1]) != 1 or not math.isfinite(count) or count < 16:
                raise RuntimeError("waiting for an actual successful scrape after check-demo traffic")
            health = get(args.grafana, "/api/health")
            if health.get("database") != "ok":
                raise RuntimeError("Grafana database is not ready")
            dashboard = get(args.grafana, "/api/dashboards/uid/shadownet-overview", True)["dashboard"]
            if dashboard.get("uid") != "shadownet-overview" or len(dashboard.get("panels", [])) != 8:
                raise RuntimeError("Grafana dashboard was not provisioned")
            datasource = get(args.grafana, "/api/datasources/uid/shadownet-prometheus/health", True)
            if datasource.get("status") != "OK":
                raise RuntimeError("Grafana cannot query its Prometheus datasource")
            break
        except urllib.error.HTTPError as failure:
            code = failure.code
            failure.close()
            # Incorrect credentials are permanent; retrying would lock the admin out.
            if code in (401, 403) or 300 <= code <= 399 or time.monotonic() >= deadline:
                raise RuntimeError("Monitoring HTTP status " + str(code)) from None
            time.sleep(0.2)
        except (OSError, ValueError, KeyError, RuntimeError) as failure:
            if time.monotonic() >= deadline:
                # Never render request headers, password, or remote response bodies.
                reason = str(failure) if isinstance(failure, RuntimeError) else type(failure).__name__
                raise RuntimeError("Monitoring check failed: " + reason) from None
            time.sleep(0.2)
    try:
        get(args.grafana, "/api/dashboards/uid/shadownet-overview")
    except urllib.error.HTTPError as failure:
        code = failure.code
        failure.close()
        if code not in (401, 403):
            raise RuntimeError("Unexpected Grafana authentication status") from None
    else:
        raise RuntimeError("Grafana dashboard unexpectedly allowed anonymous access")
    print("Verified Prometheus ingestion, 8 Grafana panels, datasource health and required authentication.")


if __name__ == "__main__":
    main()
