"""Production security controls tested against real Agent/Gateway processes."""
from datetime import datetime, timedelta, timezone
import json
import base64
import os
import shutil
import ssl
import subprocess
import sys
import time
import unittest
from reverse_proxy import ProxyHarness, ARGS, TEST_ARGS
from tunnel_peer import Peer

class Security(ProxyHarness):
    def openssl(self, *args):
        result = subprocess.run([ARGS.openssl, *map(str, args)], cwd=self.working, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, "OpenSSL fixture failed: " + result.stderr)
        return result.stdout

    def validate(self, kind, path):
        return subprocess.run([ARGS.cli, "config", "validate", "--type", kind, "--config", str(path)],
                              capture_output=True, text=True, timeout=4)

    def access(self, path):
        return self.write(path.read_text().replace("hostname: api.example.test", "access: {methods: [GET, HEAD], path_prefixes: [/echo, /fixed]}, hostname: api.example.test"))

    def crl(self, revoked=None, issuer="ca", expired=False, seconds=None):
        directory = self.working / ("crl-" + str(self.counter))
        self.counter += 1
        directory.mkdir()
        (directory / "index").write_text("")
        (directory / "number").write_text("1000\n")
        (directory / "serial").write_text("2000\n")
        config = directory / "ca.cnf"
        config.write_text('[ca]\ndefault_ca=authority\n[authority]\n' +
                          f'database="{(directory / "index").as_posix()}"\ncrlnumber="{(directory / "number").as_posix()}"\n' +
                          f'serial="{(directory / "serial").as_posix()}"\nnew_certs_dir="{directory.as_posix()}"\n' +
                          f'certificate="{(self.root / (issuer + ".crt")).as_posix()}"\nprivate_key="{(self.root / (issuer + ".key")).as_posix()}"\n' +
                          'default_md=sha256\ndefault_crl_days=1\ncrl_extensions=extensions\n[extensions]\nauthorityKeyIdentifier=keyid:always\n', encoding="ascii")
        if revoked:
            self.openssl("ca", "-batch", "-config", config, "-revoke", self.root / (revoked + ".crt"))
        output = directory / "revocations.pem"
        times = []
        if expired:
            times = ["-crl_lastupdate", "20000101000000Z", "-crl_nextupdate", "20000102000000Z"]
        elif seconds:
            times = ["-crl_nextupdate", (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime("%Y%m%d%H%M%SZ")]
        self.openssl("ca", "-batch", "-config", config, "-gencrl", "-out", output, *times)
        return output

    def with_crl(self, path, crl):
        return self.write(path.read_text().replace("security:\n", "security:\n  crl_file: " + json.dumps(crl.as_posix()) + "\n", 1))

    def test_gateway_policy_denies_before_origin_and_does_not_leak_secrets(self):
        self.gw = self.launch(ARGS.gateway, self.access(self.gateway_config(rate=1000)))
        self.gw.wait_log("wss_listening")
        self.agent()
        before = self.api.count()
        secret = "shadow-test-do-not-log-credential"
        self.assertEqual(self.call("POST", "/echo?secret=" + secret, b"private", headers={"Authorization": "Bearer " + secret})[0], 403)
        self.assertEqual(self.call(target="/fixed-other")[0], 403)
        self.assertEqual(self.api.count(), before)
        self.assertEqual(self.call(target="/fixed")[3], b"hello-api")
        self.assertEqual(self.call(target="/%66ixed")[0], 200)
        self.assertEqual(self.call("POST", "/binary", b"ok", host="app.example.test")[3], b"ok")
        self.assertNotIn(secret, self.gw.log() + self.ag.log())
        self.assertIn("http_policy_denied", self.gw.log())

    def test_agent_enforces_its_own_policy_when_gateway_is_broader(self):
        self.gateway()
        self.ag = self.launch(ARGS.agent, self.access(self.agent_config()))
        self.ag.wait_log("services_registered")
        before = self.api.count()
        self.assertEqual(self.call("DELETE", "/echo")[0], 403)
        self.assertEqual(self.api.count(), before)
        self.assertEqual(self.call(target="/fixed")[0], 200)
        self.assertIn("http_policy_denied", self.ag.log())

    def test_ambiguous_paths_never_reach_origin(self):
        self.start()
        before = self.api.count()
        for target in ("//echo", "/echo/../private", "/echo/%2e%2e/private", "/echo/%2fprivate", "/echo/%252fprivate",
                       "/echo\\private", "/echo;private", "/echo/%00", "/echo/%zz", "/echo/%c0%af"):
            self.assertEqual(self.call(target=target)[0], 400, target)
        self.assertEqual(self.api.count(), before)

    def test_access_and_rotation_schema_rejects_ambiguous_or_duplicate_rules(self):
        for kind, path in (("agent", self.agent_config()), ("gateway", self.gateway_config())):
            for policy in ("{methods: []}", "{methods: [TRACE]}", "{methods: [get]}", "{methods: [GET, GET]}",
                           "{path_prefixes: []}", "{path_prefixes: [/api/]}", "{path_prefixes: [/%61pi]}",
                           "{path_prefixes: [/a/../b]}", "{path_prefixes: ['/a?b']}", "{unknown: true}"):
                text = path.read_text().replace("hostname: api.example.test", f"access: {policy}, hostname: api.example.test")
                self.assertEqual(self.validate(kind, self.write(text)).returncode, 1, policy)
        path = self.gateway_config()
        for fingerprint in (self.fingerprint("agent"), "invalid"):
            text = path.read_text().replace("    services:\n", f"    certificate_sha256_next: {fingerprint}\n    services:\n")
            self.assertEqual(self.validate("gateway", self.write(text)).returncode, 1)

    def test_rotation_overlap_accepts_next_pin_without_changing_identity(self):
        text = self.gateway_config().read_text().replace("    services:\n", "    certificate_sha256_next: " + self.fingerprint("other-agent") + "\n    services:\n")
        self.gw = self.launch(ARGS.gateway, self.write(text))
        self.gw.wait_log("wss_listening")
        peer = Peer.connect(self.root, self.wss_port, "other-agent", "home-server")
        peer.close()
        self.gw.wait_log("tunnel_disconnected")
        self.agent()
        self.assertEqual(self.call(target="/fixed")[0], 200)

    def test_fresh_crls_accept_valid_peers_in_both_directions(self):
        crl = self.crl()
        self.gw = self.launch(ARGS.gateway, self.with_crl(self.gateway_config(), crl))
        self.gw.wait_log("wss_listening")
        self.ag = self.launch(ARGS.agent, self.with_crl(self.agent_config(), crl))
        self.ag.wait_log("services_registered")
        time.sleep(1.1)
        self.assertEqual(self.call(target="/fixed")[0], 200)

    def test_crl_revoked_agent_is_denied_even_with_matching_pin(self):
        self.gw = self.launch(ARGS.gateway, self.with_crl(self.gateway_config(), self.crl("agent")))
        self.gw.wait_log("wss_listening")
        agent = self.launch(ARGS.agent, self.agent_config())
        self.assertEqual(agent.process.wait(timeout=5), 1)
        self.assertNotIn("services_registered", self.gw.log())

    def test_crl_revoked_gateway_is_denied_by_agent(self):
        self.gateway()
        agent = self.launch(ARGS.agent, self.with_crl(self.agent_config(), self.crl("gateway")))
        self.assertEqual(agent.process.wait(timeout=5), 1)
        self.assertNotIn("services_registered", agent.log())

    def test_expired_missing_and_malformed_crls_fail_validation(self):
        malformed = self.working / "malformed.crl"
        malformed.write_text("invalid CRL")
        for path in (self.crl(expired=True), malformed, self.working / "missing.crl", self.root / "ca.crt"):
            self.assertEqual(self.validate("gateway", self.with_crl(self.gateway_config(), path)).returncode, 1)

    def test_wrong_issuer_crl_cannot_satisfy_revocation_check(self):
        self.gw = self.launch(ARGS.gateway, self.with_crl(self.gateway_config(), self.crl(issuer="rogue-ca")))
        self.gw.wait_log("wss_listening")
        agent = self.launch(ARGS.agent, self.agent_config())
        self.assertEqual(agent.process.wait(timeout=5), 1)

    def test_tampered_crl_signature_is_not_trusted(self):
        path = self.crl()
        lines = path.read_text().splitlines()
        der = bytearray(base64.b64decode("".join(lines[1:-1])))
        der[-1] ^= 1
        encoded = base64.b64encode(der).decode()
        path.write_text("-----BEGIN X509 CRL-----\n" + "\n".join(encoded[i:i+64] for i in range(0, len(encoded), 64)) + "\n-----END X509 CRL-----\n")
        self.gw = self.launch(ARGS.gateway, self.with_crl(self.gateway_config(), path))
        self.gw.wait_log("wss_listening")
        agent = self.launch(ARGS.agent, self.agent_config())
        self.assertEqual(agent.process.wait(timeout=5), 1)

    def test_crl_bundle_cannot_add_a_trusted_certificate_authority(self):
        forged = self.working / "forged-gateway.crt"
        self.openssl("x509", "-req", "-in", self.root / "gateway.csr", "-CA", self.root / "rogue-ca.crt", "-CAkey", self.root / "rogue-ca.key",
                     "-set_serial", "9000", "-days", "1", "-sha256", "-extfile", self.root / "gateway.ext", "-out", forged)
        bundle = self.working / "bundle.pem"
        bundle.write_text((self.root / "rogue-ca.crt").read_text() + self.crl().read_text() + self.crl(issuer="rogue-ca").read_text())
        gateway = self.write(self.gateway_config().read_text().replace((self.root / "gateway.crt").as_posix(), forged.as_posix()))
        self.gw = self.launch(ARGS.gateway, gateway)
        self.gw.wait_log("wss_listening")
        agent = self.launch(ARGS.agent, self.with_crl(self.agent_config(), bundle))
        self.assertEqual(agent.process.wait(timeout=3), 1)
        self.assertNotIn("services_registered", agent.log())

    def test_private_key_links_are_rejected(self):
        key = self.working / "key.pem"
        alias = self.working / "alias.pem"
        shutil.copyfile(self.root / "agent.key", key)
        self.pki.restrict_key(key)
        config = self.write(self.agent_config().read_text().replace((self.root / "agent.key").as_posix(), key.as_posix()))
        os.link(key, alias)
        try:
            self.assertEqual(self.validate("agent", config).returncode, 1)
        finally:
            alias.unlink()
        self.assertEqual(self.validate("agent", config).returncode, 0)
        if os.name != "nt":
            alias.symlink_to(key)
            link_config = self.write(config.read_text().replace(key.as_posix(), alias.as_posix()))
            self.assertEqual(self.validate("agent", link_config).returncode, 1)

    def test_crl_expiration_ends_an_established_session(self):
        crl = self.crl(seconds=5)
        self.gw = self.launch(ARGS.gateway, self.with_crl(self.gateway_config(), crl))
        self.gw.wait_log("wss_listening")
        self.agent()
        self.assertEqual(self.call(target="/fixed")[0], 200)
        self.assertEqual(self.ag.process.wait(timeout=9), 1)
        self.assertIn("credential_validation_failed", self.gw.log())
        self.assertEqual(self.call()[0], 503)

    def test_leaf_expiration_ends_an_established_session(self):
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=5)).strftime("%Y%m%d%H%M%SZ")
        certificate = self.working / "short.crt"
        self.openssl("ca", "-batch", "-notext", "-config", self.root / "authority.cnf", "-in", self.root / "agent.csr", "-out", certificate,
                     "-startdate", "20000101000000Z", "-enddate", expiry, "-extensions", "client")
        fingerprint = ssl.PEM_cert_to_DER_cert(certificate.read_text())
        import hashlib
        self.gw = self.launch(ARGS.gateway, self.write(self.gateway_config().read_text().replace(self.fingerprint("agent"), hashlib.sha256(fingerprint).hexdigest())))
        self.gw.wait_log("wss_listening")
        self.ag = self.launch(ARGS.agent, self.write(self.agent_config().read_text().replace(str((self.root / "agent.crt").as_posix()), certificate.as_posix())))
        self.ag.wait_log("services_registered")
        self.assertEqual(self.call(target="/fixed")[0], 200)
        self.assertEqual(self.ag.process.wait(timeout=9), 1)
        self.assertIn("credential_validation_failed", self.gw.log() + self.ag.log())

    def test_private_key_permissions_are_checked_on_the_runtime_platform(self):
        key = self.working / "private.key"
        shutil.copyfile(self.root / "agent.key", key)
        self.pki.restrict_key(key)
        config = self.write(self.agent_config().read_text().replace((self.root / "agent.key").as_posix(), key.as_posix()))
        self.assertEqual(self.validate("agent", config).returncode, 0)
        if os.name == "nt":
            subprocess.run([self.pki.windows_tool("icacls"), str(key), "/grant", "*S-1-1-0:R"], check=True, capture_output=True, timeout=4)
        else:
            key.chmod(0o644)
        self.assertEqual(self.validate("agent", config).returncode, 1)
        self.pki.restrict_key(key)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]] + TEST_ARGS, verbosity=2)
