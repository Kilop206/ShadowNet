"""Verify both demo services through the public HTTPS gateway, with real TLS validation."""
import argparse
import concurrent.futures
import http.client
import json
import socket
import ssl
import time


class NotReady(RuntimeError):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--requests", type=int, default=16)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--wait-seconds", type=float, default=10)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 2 <= args.requests <= 256 or not 1 <= args.concurrency <= 64 or not 0 <= args.wait_seconds <= 30:
        parser.error("invalid port, request count or concurrency")
    context = ssl.create_default_context(cafile=args.ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    def check(index):
        host, service, path = ("api.example.test", "api", "/health") if index % 2 == 0 else ("app.example.test", "website", "/")
        connection = http.client.HTTPConnection(host, args.port, timeout=5)
        raw = socket.create_connection((args.address, args.port), timeout=5)
        try:
            # Pin only the TCP endpoint; SNI and certificate checks use the public hostname.
            connection.sock = context.wrap_socket(raw, server_hostname=host)
            connection.request("GET", path)
            response = connection.getresponse()
            body = response.read()
            if response.status in (502, 503):
                raise NotReady("service is not ready: " + host + ": " + str(response.status))
            if response.status != 200 or response.getheader("X-Service") != service:
                raise RuntimeError("unexpected response for " + host + ": " + str(response.status))
            if service == "api" and json.loads(body).get("service") != "shadow-example-api":
                raise RuntimeError("API identity mismatch")
            if service == "website" and b"<h1>ShadowNet</h1>" not in body:
                raise RuntimeError("website identity mismatch")
        finally:
            connection.close()
            raw.close()

    # Only repeat safe GET readiness probes; TLS failures and identity mismatches
    # always fail immediately. Actual batch requests are never retried.
    if args.wait_seconds:
        deadline = time.monotonic() + args.wait_seconds
        while True:
            try:
                check(0)
                check(1)
                break
            except (NotReady, ConnectionError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        list(pool.map(check, range(args.requests)))
    print(f"Verified {args.requests} HTTPS requests across 2 services (concurrency={args.concurrency}, TLS certificates verified).")


if __name__ == "__main__":
    main()
