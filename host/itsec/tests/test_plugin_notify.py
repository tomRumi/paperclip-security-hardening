"""The "plugin" channel: alerts, heartbeat, enrolment and removal posted to the Security hardening plugin's webhook,
signed with an Ed25519 key through the openssl CLI. Signatures are checked here with openssl; the plugin side checks
the same format (plugin/test/hostinstall.test.mjs, "a signature made with openssl ... verifies")."""
import _bootstrap  # noqa: F401
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from helpers import FakeWebhook, make_cfg
from itsec import notify
from itsec.core import make_finding

T = 1760335200.0
HAVE_OPENSSL = shutil.which("openssl") is not None
BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "itsec-plugin")


@unittest.skipUnless(HAVE_OPENSSL, "openssl not installed")
class PluginWebhookNotifier(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.key = os.path.join(self.d, "watchdog-key.pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", self.key], check=True, capture_output=True)
        self.pub = os.path.join(self.d, "pub.pem")
        subprocess.run(["openssl", "pkey", "-in", self.key, "-pubout", "-out", self.pub], check=True, capture_output=True)
        self.srv = FakeWebhook()
        self.addCleanup(self.srv.close)
        self.url = self.srv.url + "/api/plugins/paperclip-security-hardening/webhooks/watchdog"
        self.n = notify.PluginWebhookNotifier(self.url, "inst-0001", self.key, version="1.0.0")

    def verify(self, req):
        sig = os.path.join(self.d, "sig")
        msg = os.path.join(self.d, "msg")
        with open(sig, "wb") as f:
            f.write(base64.b64decode(req["headers"]["x-pcsh-signature"]))
        with open(msg, "wb") as f:
            f.write(b"pcsh-v1\n" + req["raw"])
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", self.pub, "-in", msg, "-sigfile", sig], capture_output=True)
        return r.returncode == 0

    def alert(self):
        f = make_finding("sudo-attempt", "HIGH", "sudo attempt by the agent user", "journal", ["evidence"], "sudo-attempt:d", T)
        return notify.alert_for_finding(f)

    def test_alert_is_signed_and_carries_install_ts_nonce(self):
        ok, info = self.n.send(self.alert())
        self.assertEqual((ok, info), (True, "delivered"))
        req = self.srv.requests[0]
        self.assertEqual(req["path"], "/api/plugins/paperclip-security-hardening/webhooks/watchdog")
        self.assertTrue(self.verify(req))
        body = json.loads(req["raw"])
        self.assertEqual((body["type"], body["installId"]), ("alert", "inst-0001"))
        self.assertRegex(body["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertRegex(body["nonce"], r"^[A-Za-z0-9_-]{16,64}$")
        self.assertEqual(body["alert"]["key"], "sudo-attempt:d")
        self.assertTrue(body["alert"]["title"].startswith("[ITSec HIGH]"))
        self.assertNotIn("authorization", req["headers"])            # no Paperclip key on this channel
        # A changed byte breaks the signature.
        self.assertFalse(self.verify(dict(req, raw=req["raw"].replace(b"inst-0001", b"inst-0002"))))
        # Every message gets a fresh nonce.
        self.n.send(self.alert())
        self.assertNotEqual(json.loads(self.srv.requests[1]["raw"])["nonce"], body["nonce"])

    def test_no_private_key_material_leaves_the_host(self):
        self.n.enrol("ABCD-EFGH-JKMN-PQRS", host="host1")
        self.n.heartbeat({"findings": 1})
        with open(self.key, "rb") as f:
            pem = f.read()
        der_tail = base64.b64decode(b"".join(pem.split(b"\n")[1:-2]))[-32:]          # the raw private scalar
        for req in self.srv.requests:
            blob = req["raw"] + json.dumps(req["headers"]).encode()
            self.assertNotIn(pem.split(b"\n")[1], blob)
            self.assertNotIn(base64.b64encode(der_tail), blob)
            self.assertNotIn(der_tail, blob)

    def test_enrol_sends_code_and_public_key(self):
        ok, _ = self.n.enrol("ABCD-EFGH-JKMN-PQRS", host="host1")
        self.assertTrue(ok)
        req = self.srv.requests[0]
        self.assertTrue(self.verify(req))
        body = json.loads(req["raw"])
        self.assertEqual((body["type"], body["code"], body["host"], body["version"]), ("enrol", "ABCD-EFGH-JKMN-PQRS", "host1", "1.0.0"))
        der = subprocess.run(["openssl", "pkey", "-in", self.key, "-pubout", "-outform", "DER"], capture_output=True).stdout
        self.assertEqual(base64.b64decode(body["publicKey"]), der)

    def test_heartbeat_and_unenrol(self):
        self.assertTrue(self.n.heartbeat({"findings": 2, "highSent": 0, "deliveryFailed": 0})[0])
        self.assertTrue(self.n.unenrol()[0])
        b1, b2 = (json.loads(r["raw"]) for r in self.srv.requests)
        self.assertEqual((b1["type"], b1["summary"]["findings"], b1["version"]), ("heartbeat", 2, "1.0.0"))
        self.assertEqual(b2["type"], "unenrol")

    def test_refusal_is_a_failure_with_the_plugin_reason(self):
        self.srv.status, self.srv.reply = 502, {"deliveryId": "d", "status": "failed", "error": "watchdog webhook rejected: no alert company configured"}
        ok, info = self.n.send(self.alert())
        self.assertFalse(ok)
        self.assertEqual(info, "http 502: watchdog webhook rejected: no alert company configured")

    def test_unreadable_key_or_missing_config_fails_closed_without_posting(self):
        bad = notify.PluginWebhookNotifier(self.url, "inst-0001", self.d + "/missing.pem")
        ok, info = bad.send(self.alert())
        self.assertFalse(ok)
        self.assertIn("signing failed", info)
        self.assertFalse(notify.PluginWebhookNotifier("", "", self.key).send(self.alert())[0])
        self.assertEqual(self.srv.requests, [])
        self.assertEqual(bad.verify_alerts({"i": {}}), [])

    def test_build_notifier_and_multi_heartbeat(self):
        cfg = make_cfg(self.d, notifier="plugin")
        cfg["plugin"] = {"url": self.url, "install_id": "inst-0001", "key_file": self.key, "openssl": "openssl", "version": "2"}
        n = notify.build_notifier(cfg)
        self.assertIsInstance(n, notify.PluginWebhookNotifier)
        cfg["notifier"] = ["plugin", "log"]
        m = notify.build_notifier(cfg)
        ok, info = m.heartbeat({})
        self.assertTrue(ok)
        self.assertEqual(info, "plugin:delivered")
        # The default config keeps the Paperclip API channel (its own key) as the alternative.
        self.assertEqual(make_cfg(self.d)["notifier"], "paperclip")

    def test_cli_reads_the_code_from_stdin_and_never_prints_it(self):
        cfg = os.path.join(self.d, "config.json")
        with open(cfg, "w") as f:
            json.dump({"notifier": "plugin", "plugin": {"url": self.url, "install_id": "inst-0001", "key_file": "/nonexistent"}}, f)
        r = subprocess.run([sys.executable, "-I", "-B", BIN, "--config", cfg, "--key", self.key, "enrol"], input=b"WXYZ-2345-6789-ABCD\n", capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(b"WXYZ", r.stdout + r.stderr)
        self.assertEqual(json.loads(self.srv.requests[0]["raw"])["code"], "WXYZ-2345-6789-ABCD")
        self.srv.status = 502
        r = subprocess.run([sys.executable, "-I", "-B", BIN, "--config", cfg, "--key", self.key, "heartbeat"], capture_output=True)
        self.assertEqual(r.returncode, 1)
        r = subprocess.run([sys.executable, "-I", "-B", BIN, "--config", cfg, "enrol"], input=b"", capture_output=True)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
