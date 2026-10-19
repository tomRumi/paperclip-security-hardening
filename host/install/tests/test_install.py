"""The one-line installers and the release script, in a scratch directory only (never as root, never on the system):
scripts/release.sh builds a release with a file:// download URL, then install-watchdog.sh and
install-hermes-wrapper.sh run with --prefix (a fake root: no useradd/systemctl/chown, "would run" lines instead).
A local HTTP server stands in for the plugin webhook and checks the enrolment signature with openssl.
  PCSH_TEST_SCRATCH  parent directory for the scratch files (default: the OS temp dir)
Run: cd host/install && python3 -I -B -m unittest discover -s tests"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

PKG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CODE = "WXYZ-2345-6789-ABCD"
NEEDED = all(shutil.which(c) for c in ("openssl", "curl", "sha256sum", "tar", "gzip", "bash"))


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class Webhook:
    """Records each POST (raw body, headers); answers `status`."""

    def __init__(self):
        self.requests, self.status = [], 200
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.requests.append({"path": self.path, "raw": raw, "headers": {k.lower(): v for k, v in self.headers.items()}})
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success" if outer.status == 200 else "failed", "error": "watchdog webhook rejected: enrolment code expired"}).encode())

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@unittest.skipUnless(NEEDED, "openssl, curl, sha256sum, tar, gzip and bash are needed")
class Installers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="pcsh-install-test-", dir=os.environ.get("PCSH_TEST_SCRATCH"))
        cls.dist = os.path.join(cls.tmp, "dist")
        cls.pins = os.path.join(cls.tmp, "pins.json")
        r = subprocess.run(["bash", os.path.join(PKG, "scripts", "release.sh"), "--version", "9.9.9", "--base-url", f"file://{cls.dist}/",
                            "--out", cls.dist, "--pins-file", cls.pins], capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError(r.stderr)
        cls.release_out = r.stdout
        cls.n = 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        Installers.n += 1
        self.root = os.path.join(self.tmp, f"root-{self.n}")
        self.hook = Webhook()
        self.addCleanup(self.hook.close)

    def install(self, *args, script="install-watchdog.sh", dist=None, env=None):
        cmd = ["bash", os.path.join(dist or self.dist, script), "--prefix", self.root, *args]
        return subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ, **(env or {})))

    def p(self, rel):
        return os.path.join(self.root, rel.lstrip("/"))

    def read(self, rel):
        with open(self.p(rel), "rb") as f:
            return f.read()

    def verify(self, req):
        body = json.loads(req["raw"])
        d = tempfile.mkdtemp(dir=self.tmp)
        try:
            with open(os.path.join(d, "pub.der"), "wb") as f:
                f.write(base64.b64decode(body["publicKey"]))
            with open(os.path.join(d, "msg"), "wb") as f:
                f.write(b"pcsh-v1\n" + req["raw"])
            with open(os.path.join(d, "sig"), "wb") as f:
                f.write(base64.b64decode(req["headers"]["x-pcsh-signature"]))
            r = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", os.path.join(d, "pub.der"),
                                "-in", os.path.join(d, "msg"), "-sigfile", os.path.join(d, "sig")], capture_output=True)
            return r.returncode == 0
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # ------------------------------------------------------------------ release
    def test_release_pins_the_fingerprints_into_the_installers_and_the_plugin_pins(self):
        with open(self.pins) as f:
            pins = json.load(f)
        self.assertEqual(pins["version"], "9.9.9")
        self.assertEqual(pins["installWatchdogSha256"], sha(os.path.join(self.dist, "install-watchdog.sh")))
        self.assertEqual(pins["installHermesSha256"], sha(os.path.join(self.dist, "install-hermes-wrapper.sh")))
        self.assertEqual(pins["hermesWrapperSha256"], sha(os.path.join(PKG, "host", "sandbox", "hermes-sandbox")))
        self.assertIn(f"{pins['installWatchdogSha256']}  install-watchdog.sh", self.release_out)
        with open(os.path.join(self.dist, "install-watchdog.sh")) as f:
            text = f.read()
        self.assertIn(f'BUNDLE_SHA256="{sha(os.path.join(self.dist, "paperclip-watchdog-9.9.9.tar.gz"))}"', text)
        self.assertNotIn("__BUNDLE_SHA256__", text)
        names = subprocess.run(["tar", "-tzf", os.path.join(self.dist, "paperclip-watchdog-9.9.9.tar.gz")], capture_output=True, text=True).stdout.split()
        self.assertIn("paperclip-watchdog/bin/itsec-plugin", names)
        self.assertFalse([n for n in names if "__pycache__" in n or "/tests/" in n])
        r = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=self.dist, capture_output=True)
        self.assertEqual(r.returncode, 0)
        # The development checkout's pins stay empty (release.sh wrote to the scratch file only).
        with open(os.path.join(PKG, "plugin", "src", "release-pins.json")) as f:
            self.assertIsNone(json.load(f)["installWatchdogSha256"])

    # ------------------------------------------------------------------ watchdog
    def test_prefix_install_with_enrolment(self):
        r = self.install("--paperclip", self.hook.url, "--enrol", CODE)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout + r.stderr
        self.assertNotIn(CODE, out, "the code is never echoed")
        self.assertNotIn("PRIVATE KEY", out)
        # code, config, key, units
        for rel in ("opt/itsec/bin/itsec-collect", "opt/itsec/bin/itsec-plugin", "opt/itsec/itsec/notify.py", "opt/itsec/VERSION",
                    "etc/itsec/config.json", "etc/itsec/watchdog-key.pem", "etc/itsec/install-id",
                    "etc/systemd/system/itsec-collect.service", "etc/systemd/system/itsec-collect.timer", "etc/systemd/system/itsec-report.service",
                    "etc/systemd/system/itsec-report.timer", "etc/systemd/system/itsec-lynis.service", "etc/systemd/system/itsec-lynis.timer"):
            self.assertTrue(os.path.exists(self.p(rel)), rel)
        self.assertFalse(os.path.exists(self.p("opt/itsec/tests")))
        self.assertEqual(os.stat(self.p("etc/itsec/watchdog-key.pem")).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.p("opt/itsec/bin/itsec-collect")).st_mode & 0o022, 0)
        with open(self.p("etc/itsec/config.json")) as f:
            cfg = json.load(f)
        self.assertEqual(cfg["notifier"], "plugin")
        self.assertEqual(cfg["plugin"]["url"], f"{self.hook.url}/api/plugins/paperclip-sandbox-hardening/webhooks/watchdog")
        self.assertEqual(cfg["plugin"]["key_file"], "${CREDENTIALS_DIRECTORY}/watchdog-key")
        self.assertRegex(cfg["plugin"]["install_id"], r"^inst-[0-9a-f]{24}$")
        self.assertNotIn(CODE, json.dumps(cfg))
        with open(self.p("etc/systemd/system/itsec-collect.service")) as f:
            unit = f.read()
        self.assertIn("LoadCredential=watchdog-key:/etc/itsec/watchdog-key.pem", unit)
        self.assertNotIn("paperclip-token", unit)
        self.assertNotIn("idempotency-secret", unit)
        self.assertIn("IPAddressAllow=127.0.0.1 127.0.0.0/8", unit)
        with open(self.p("etc/systemd/system/itsec-report.service")) as f:
            self.assertNotIn("claude-token", f.read())                     # no such credential on this host
        # system changes are only printed in a prefix install
        for line in ("would run: useradd --system --home-dir /var/lib/itsec --no-create-home --shell /usr/sbin/nologin itsec",
                     "would run: usermod -aG adm,systemd-journal,vaultaudit itsec", "would run: systemctl start itsec-collect.service",
                     "would run: systemctl enable --now itsec-collect.timer itsec-report.timer itsec-lynis.timer"):
            self.assertIn(line, r.stdout)
        # the enrolment: code + public key, signed by the new key; no private key material
        self.assertEqual(len(self.hook.requests), 1)
        req = self.hook.requests[0]
        self.assertEqual(req["path"], "/api/plugins/paperclip-sandbox-hardening/webhooks/watchdog")
        body = json.loads(req["raw"])
        self.assertEqual((body["type"], body["code"], body["installId"]), ("enrol", CODE, cfg["plugin"]["install_id"]))
        self.assertTrue(self.verify(req))
        with open(self.p("etc/itsec/watchdog-key.pem"), "rb") as f:
            self.assertNotIn(f.read().split(b"\n")[1], req["raw"])

    def test_rerun_is_idempotent_and_keeps_key_id_and_config(self):
        self.assertEqual(self.install("--paperclip", self.hook.url).returncode, 0)
        key, iid = self.read("etc/itsec/watchdog-key.pem"), self.read("etc/itsec/install-id")
        with open(self.p("etc/itsec/config.json")) as f:
            cfg = json.load(f)
        cfg["watch"] = [{"severity": "HIGH", "globs": ["/etc/custom"]}]           # an admin edit survives
        with open(self.p("etc/itsec/config.json"), "w") as f:
            json.dump(cfg, f)
        os.makedirs(self.p("opt/itsec/itsec/__pycache__"), exist_ok=True)
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.read("etc/itsec/watchdog-key.pem"), key)
        self.assertEqual(self.read("etc/itsec/install-id"), iid)
        with open(self.p("etc/itsec/config.json")) as f:
            again = json.load(f)
        self.assertEqual(again["watch"], cfg["watch"])
        self.assertEqual(again["plugin"]["url"], cfg["plugin"]["url"])
        self.assertFalse(os.path.exists(self.p("opt/itsec/itsec/__pycache__")))
        self.assertEqual(self.hook.requests, [], "no enrolment without --enrol")

    def test_sha_mismatch_stops_before_anything_is_installed(self):
        bad = os.path.join(self.tmp, f"dist-bad-{self.n}")
        shutil.copytree(self.dist, bad)
        with open(os.path.join(bad, "paperclip-watchdog-9.9.9.tar.gz"), "ab") as f:
            f.write(b"\0")
        r = self.install("--paperclip", self.hook.url, "--enrol", CODE, "--base-url", f"file://{bad}/")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fingerprint does not match", r.stderr)
        self.assertFalse(os.path.exists(self.p("opt/itsec")))
        self.assertFalse(os.path.exists(self.p("etc/itsec")))
        self.assertNotIn("would run: useradd", r.stdout)
        self.assertEqual(self.hook.requests, [])
        self.assertNotIn(CODE, r.stdout + r.stderr)

    def test_failed_enrolment_fails_without_echoing_the_code(self):
        self.hook.status = 502
        r = self.install("--paperclip", self.hook.url, "--enrol", CODE)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("enrolment failed", r.stderr)
        self.assertNotIn(CODE, r.stdout + r.stderr)
        self.assertTrue(os.path.exists(self.p("etc/itsec/watchdog-key.pem")), "files stay: re-running with a new code is safe")

    def test_uninstall_cleans_the_prefix_and_tells_the_plugin(self):
        self.assertEqual(self.install("--paperclip", self.hook.url, "--enrol", CODE).returncode, 0)
        r = self.install("--uninstall")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("would run: systemctl disable --now itsec-collect.timer itsec-report.timer itsec-lynis.timer", r.stdout)
        self.assertIn("would run: userdel itsec", r.stdout)
        for rel in ("opt/itsec", "etc/itsec", "var/lib/itsec"):
            self.assertFalse(os.path.exists(self.p(rel)), rel)
        self.assertEqual(os.listdir(self.p("etc/systemd/system")), [])
        self.assertEqual(json.loads(self.hook.requests[-1]["raw"])["type"], "unenrol")
        self.assertEqual(self.install("--uninstall").returncode, 0, "idempotent")

    def test_refusals(self):
        src = os.path.join(PKG, "host", "install")
        r = self.install("--paperclip", self.hook.url, dist=src)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a release build", r.stderr)
        r = self.install("--paperclip", self.hook.url, "--base-url", "http://example.invalid/")
        self.assertIn("must be https://", r.stderr)
        r = self.install("--paperclip", "ftp://x", "--enrol", CODE)
        self.assertIn("--paperclip must be", r.stderr)
        r = self.install("--paperclip", self.hook.url, "--enrol", "bad code; rm -rf /")
        self.assertIn("malformed", r.stderr)
        self.assertNotIn("rm -rf", r.stderr)
        r = self.install()
        self.assertIn("first install: --paperclip URL is required", r.stderr)
        if os.getuid() != 0:                                           # without --prefix: root (sudo) only
            for script in ("install-watchdog.sh", "install-hermes-wrapper.sh"):
                r = subprocess.run(["bash", os.path.join(self.dist, script), "--paperclip", self.hook.url][: 2 if "hermes" in script else 4],
                                   capture_output=True, text=True)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("run this with sudo", r.stderr)

    # ------------------------------------------------------------------ Hermes wrapper
    def test_hermes_install_mismatch_and_uninstall(self):
        r = self.install(script="install-hermes-wrapper.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        target = self.p("usr/local/bin/hermes-sandbox")
        self.assertEqual(sha(target), sha(os.path.join(PKG, "host", "sandbox", "hermes-sandbox")))
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o755)
        self.assertIn("would run: chown root:root", r.stdout)
        self.assertEqual(self.install(script="install-hermes-wrapper.sh").returncode, 0, "idempotent")
        r = self.install("--path", "/opt/bin/hermes-box", script="install-hermes-wrapper.sh")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(self.p("opt/bin/hermes-box")))
        self.assertNotEqual(self.install("--path", "relative/x", script="install-hermes-wrapper.sh").returncode, 0)
        bad = os.path.join(self.tmp, f"dist-badw-{self.n}")
        shutil.copytree(self.dist, bad)
        with open(os.path.join(bad, "hermes-sandbox"), "a") as f:
            f.write("// tampered\n")
        os.remove(target)
        r = self.install("--base-url", f"file://{bad}/", script="install-hermes-wrapper.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fingerprint does not match", r.stderr)
        self.assertFalse(os.path.exists(target))
        self.assertEqual(self.install("--uninstall", "--path", "/opt/bin/hermes-box", script="install-hermes-wrapper.sh").returncode, 0)
        self.assertFalse(os.path.exists(self.p("opt/bin/hermes-box")))


if __name__ == "__main__":
    unittest.main()
