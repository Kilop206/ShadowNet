"""Generate a disposable CA and WSS configurations, never production credentials.

Requires the OpenSSL command-line tool. Refuses to overwrite existing outputs.
On Windows, restrict the output directory's ACL before using it outside a lab.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import ssl
import subprocess


def generate(directory, openssl="openssl", test_fixtures=False):
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    if os.name != "nt":
        directory.chmod(0o700)
    (directory / "request.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")

    def run(*arguments):
        if arguments[0] == "req":
            arguments = (*arguments, "-config", "request.cnf")
        result = subprocess.run([openssl, *map(str, arguments)], cwd=directory, capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError("OpenSSL fixture generation failed: " + " ".join(str(a) for a in arguments[:2]))

    def root(name):
        run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-noenc",
            "-keyout", name + ".key", "-out", name + ".crt", "-days", "2", "-sha256", "-subj", "/CN=ShadowNet Development CA",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")

    serial = 10

    def leaf(name, purpose="clientAuth", signer="ca", san=None):
        nonlocal serial
        run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-noenc",
            "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + name)
        extension = ("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\n"
                     "authorityKeyIdentifier=keyid,issuer\nextendedKeyUsage=" + purpose + "\n")
        if san:
            extension += "subjectAltName=" + san + "\n"
        (directory / (name + ".ext")).write_text(extension, encoding="ascii")
        run("x509", "-req", "-in", name + ".csr", "-CA", signer + ".crt", "-CAkey", signer + ".key", "-set_serial", serial,
            "-out", name + ".crt", "-days", "2", "-sha256", "-extfile", name + ".ext")
        serial += 1

    root("ca")
    leaf("gateway", "serverAuth", san="DNS:localhost,DNS:gateway,DNS:api.example.test,DNS:app.example.test,IP:127.0.0.1,IP:::1")
    leaf("agent")
    if test_fixtures:
        leaf("other-agent")
        root("rogue-ca")
        leaf("rogue-agent", signer="rogue-ca")
        leaf("wrong-host", "serverAuth", san="DNS:wrong.example.test")
        leaf("wrong-purpose", "serverAuth")
        (directory / "newcerts").mkdir()
        (directory / "index.txt").write_text("", encoding="ascii")
        (directory / "serial").write_text("1000\n", encoding="ascii")
        config = ('[ca]\ndefault_ca=authority\n[authority]\ndir="' + directory.as_posix() + '"\n'
                  'database=$dir/index.txt\nserial=$dir/serial\nnew_certs_dir=$dir/newcerts\n'
                  'certificate=$dir/ca.crt\nprivate_key=$dir/ca.key\ndefault_md=sha256\n'
                  'policy=policy\nunique_subject=no\n[policy]\ncommonName=supplied\n'
                  '[client]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\n'
                  'authorityKeyIdentifier=keyid,issuer\nextendedKeyUsage=clientAuth\n'
                  '[server]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                  'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n'
                  'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
        (directory / "authority.cnf").write_text(config, encoding="ascii")
        for name, csr, extension in (("expired-agent", "agent", "client"), ("expired-gateway", "gateway", "server")):
            run("ca", "-batch", "-notext", "-config", "authority.cnf", "-in", csr + ".csr", "-out", name + ".crt",
                "-startdate", "20000101000000Z", "-enddate", "20000102000000Z", "-extensions", extension)
            shutil.copyfile(directory / (csr + ".key"), directory / (name + ".key"))
    for key in directory.glob("*.key"):
        if os.name != "nt":
            key.chmod(0o600)
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert((directory / "agent.crt").read_text(encoding="ascii"))).hexdigest()
    security = "security:\n  ca_file: ca.crt\n  certificate_file: {certificate}.crt\n  private_key_file: {certificate}.key\n"
    services = ("services:\n  - name: api\n    hostname: api.example.test\n    local_host: 127.0.0.1\n    local_port: 8080\n"
                "  - name: website\n    hostname: app.example.test\n    local_host: 127.0.0.1\n    local_port: 3000\n")
    policy = ("    services:\n      - {name: api, hostname: api.example.test}\n"
              "      - {name: website, hostname: app.example.test}\n")
    public = ("http:\n  bind_host: 127.0.0.1\n  port: 8443\n  max_connections: 32\n  max_in_flight: 16\n"
              "  requests_per_second: 100\n  request_timeout_ms: 5000\n  security:\n"
              "    certificate_file: gateway.crt\n    private_key_file: gateway.key\n")
    (directory / "agent.wss.yaml").write_text(
        "transport: wss\nagent:\n  name: home-server\n  gateway_host: localhost\n  port: 7443\n  timeout_ms: 3000\n"
        "  reconnect:\n    enabled: true\n    initial_ms: 250\n    max_ms: 30000\n" + security.format(certificate="agent") + services, encoding="utf-8")
    (directory / "gateway.wss.yaml").write_text(
        "transport: wss\ngateway:\n  bind_host: 127.0.0.1\n  port: 7443\n  timeout_ms: 3000\n  max_connections: 64\n"
        "  heartbeat_interval_ms: 1000\n  heartbeat_timeout_ms: 3000\n" + security.format(certificate="gateway") +
        "authorized_agents:\n  - name: home-server\n    certificate_sha256: " + fingerprint + "\n" + policy + public, encoding="utf-8")
    (directory / "agent.compose.yaml").write_text(
        (directory / "agent.wss.yaml").read_text(encoding="utf-8").replace("gateway_host: localhost", "gateway_host: gateway")
        .replace("private_key_file: agent.key", "private_key_file: private/leaf.key"), encoding="utf-8")
    (directory / "gateway.compose.yaml").write_text(
        (directory / "gateway.wss.yaml").read_text(encoding="utf-8").replace("bind_host: 127.0.0.1", "bind_host: 0.0.0.0")
        .replace("private_key_file: gateway.key", "private_key_file: private/leaf.key"), encoding="utf-8")
    return fingerprint


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="build/dev-pki")
    parser.add_argument("--openssl", default="openssl")
    options = parser.parse_args()
    fingerprint = generate(options.output, options.openssl)
    print("Development certificates/configurations created in " + str(Path(options.output).resolve()))
    print("Agent certificate SHA-256: " + fingerprint)
