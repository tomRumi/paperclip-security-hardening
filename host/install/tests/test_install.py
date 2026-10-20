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
import re
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

PKG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
CODE = "WXYZ-2345-6789-ABCD"
NEEDED_TOOLS = ("openssl", "curl", "sha256sum", "tar", "gzip", "bash", "python3", "install", "realpath", "mktemp", "getent", "sed", "awk", "sort", "id", "cut", "tr", "od", "dirname", "chmod", "find", "cp", "mv", "rm", "mkdir", "cat", "grep", "tail")
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
        # A stand-in `lynis` in front of the PATH, so the installs below see lynis whether or not this machine has it.
        cls.stubs = os.path.join(cls.tmp, "stubs")
        os.makedirs(cls.stubs)
        with open(os.path.join(cls.stubs, "lynis"), "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(os.path.join(cls.stubs, "lynis"), 0o755)

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
        base = {**os.environ, "SUDO_USER": "", "PATH": self.stubs + os.pathsep + os.environ["PATH"]}
        return subprocess.run(cmd, capture_output=True, text=True, env={**base, **(env or {})})

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
        # The package's own pins are untouched (release.sh wrote to the scratch file only): either empty (a development
        # checkout) or the real hashes of a published release, never this test's 9.9.9 build.
        with open(os.path.join(PKG, "plugin", "src", "release-pins.json")) as f:
            own = json.load(f)
        self.assertNotEqual(own["version"], "9.9.9")
        self.assertNotEqual(own["installWatchdogSha256"], pins["installWatchdogSha256"])
        for k in ("installWatchdogSha256", "installHermesSha256", "hermesWrapperSha256"):
            self.assertTrue(own[k] is None or re.fullmatch(r"[0-9a-f]{64}", own[k]), k)

    # ------------------------------------------------------------------ watchdog
    def test_prefix_install_with_enrolment(self):
        r = self.install("--paperclip", self.hook.url, "--enrol", CODE)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout + r.stderr
        self.assertNotIn(CODE, out, "the code is never echoed")
        self.assertNotIn("PRIVATE KEY", out)
        # code, config, key, units
        for rel in ("opt/itsec/bin/itsec-collect", "opt/itsec/bin/itsec-plugin", "opt/itsec/bin/itsec-acl", "opt/itsec/itsec/acl.py", "opt/itsec/itsec/notify.py", "opt/itsec/VERSION", "opt/itsec/fail2ban/jail.local", "opt/itsec/INSTALL.md",
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
        self.assertEqual(cfg["plugin"]["url"], f"{self.hook.url}/api/plugins/paperclip-security-hardening/webhooks/watchdog")
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
                     "would run: systemctl enable --now itsec-collect.timer itsec-report.timer itsec-lynis.timer"):   # lynis is on the PATH
            self.assertIn(line, r.stdout)
        # the enrolment: code + public key, signed by the new key; no private key material
        self.assertEqual(len(self.hook.requests), 1)
        req = self.hook.requests[0]
        self.assertEqual(req["path"], "/api/plugins/paperclip-security-hardening/webhooks/watchdog")
        body = json.loads(req["raw"])
        self.assertEqual((body["type"], body["code"], body["installId"]), ("enrol", CODE, cfg["plugin"]["install_id"]))
        self.assertTrue(self.verify(req))
        with open(self.p("etc/itsec/watchdog-key.pem"), "rb") as f:
            self.assertNotIn(f.read().split(b"\n")[1], req["raw"])

    def config(self):
        with open(self.p("etc/itsec/config.json")) as f:
            return json.load(f)

    def test_watched_and_admin_user_go_into_a_new_config(self):
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser", "--admin-user", "ops", env={"SUDO_USER": "someone"})
        self.assertEqual(r.returncode, 0, r.stderr)
        cfg = self.config()
        self.assertEqual((cfg["watched_user"], cfg["admin_user"]), ("pcuser", "ops"), "the flag wins over $SUDO_USER")
        # The watch list follows the watched account's home instead of the example's /home/paperclip.
        globs = [g for w in cfg["watch"] for g in w["globs"] + w.get("exclude", [])]
        self.assertIn("/home/pcuser/.claude/settings.json", globs)
        self.assertIn("/home/pcuser/.paperclip/cli/current/node_modules/@paperclipai/server/dist/routes/agents.js", globs)
        self.assertIn("/home/pcuser/.claude/plugins/marketplaces/*/.gcs-sha", globs)
        self.assertFalse([g for g in globs if "/home/paperclip" in g], "no leftover example home")
        self.assertIn("/home/*/.ssh/authorized_keys", globs, "other users' paths are untouched")
        # a re-run keeps the config, and says so, whatever the options are now
        r = self.install("--watched-user", "other", "--admin-user", "x")
        self.assertIn("kept the existing config (watched_user pcuser, admin_user ops)", r.stdout)
        self.assertIn("--watched-user other is ignored", r.stdout)
        self.assertEqual(self.config()["watched_user"], "pcuser")

    def test_admin_user_defaults_to_the_sudo_account_else_stays_and_says_so(self):
        r = self.install("--paperclip", self.hook.url, env={"SUDO_USER": "opsadmin"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.config()["admin_user"], "opsadmin")
        self.assertIn("admin account: opsadmin (the account that ran sudo)", r.stdout)
        for sudo_user in ("", "root", "paperclip", "Not Valid"):               # no usable sudo account: the example value stays
            self.root = os.path.join(self.tmp, f"root-nosudo-{sudo_user.replace(' ', '_')}")
            r = self.install("--paperclip", self.hook.url, env={"SUDO_USER": sudo_user})
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(self.config()["admin_user"], "admin", sudo_user)
            self.assertIn('admin account unknown', r.stdout)
            self.assertIn('admin_user stays "admin"', r.stdout)
        self.assertIn("--admin-user is not a valid user name", self.install("--paperclip", self.hook.url, "--admin-user", "a b").stderr)

    def test_no_vault_on_the_host_switches_the_vault_check_off(self):
        self.assertEqual(self.install("--paperclip", self.hook.url).returncode, 0)
        self.assertEqual(self.config()["vault_audit_log"], "")
        self.root = os.path.join(self.tmp, f"root-vault-{self.n}")
        os.makedirs(self.p("var/log/vault"))
        self.assertEqual(self.install("--paperclip", self.hook.url).returncode, 0)
        self.assertEqual(self.config()["vault_audit_log"], "/var/log/vault/audit.jsonl")

    # ------------------------------------------------------------------ read access and manifest
    def paperclip_home(self, user="pcuser"):
        """A fake watched home: watched files, a secret that must not be granted, a symlink that must be skipped, a patched Paperclip tree."""
        home = self.p(f"home/{user}")
        ns = {}
        with open(os.path.join(PKG, "host", "itsec", "bin", "itsec-make-manifest")) as f:
            exec(f.read().split("def main")[0].split("import tempfile")[1], ns)
        tree = os.path.join(home, ".paperclip", "cli", "installs", "npm", "2026.1012.0")
        for rel, markers in ns["TREE_TARGETS"]:
            markers = [m for m in markers if m not in ns["OPTIONAL_MARKERS"]]
            if markers:
                self.write(os.path.join(tree, rel), "".join(m + "\n" for m in markers))
        os.symlink("installs/npm/2026.1012.0", os.path.join(home, ".paperclip", "cli", "current"))
        for rel in (".claude/settings.json", ".claude/skills/s1/SKILL.md", ".ssh/authorized_keys", ".bashrc", ".config/systemd/user/a.service",
                    ".paperclip/instances/default/companies/c1/agents/a1/.claude/settings.json",
                    ".paperclip/instances/default/companies/c1/agents/a1/.claude/projects/chat.jsonl",   # a conversation: never granted
                    ".claude/.credentials.json", ".ssh/id_ed25519", ".paperclip/instances/default/secrets/master.key"):
            self.write(os.path.join(home, rel), "x\n")
        os.symlink("/etc/passwd", os.path.join(home, ".bash_logout"))
        return os.path.realpath(home)

    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    def acl_calls(self, out, op=None):
        """The "would run: python3 -I -B .../bin/itsec-acl --uid N <op> <kind> <path>" lines as (op, kind, path)."""
        calls = []
        for l in out.splitlines():
            m = re.fullmatch(r"would run: python3 -I -B \S+/opt/itsec/bin/itsec-acl --uid (\d+) (grant|remove) ([xrR]) (/.+)", l)
            if m:
                self.assertEqual(int(m.group(1)), os.getuid())
                if op in (None, m.group(2)):
                    calls.append((m.group(2), m.group(3), m.group(4)))
        return calls

    def test_read_access_goes_to_exactly_the_watched_files_and_the_manifest_is_written(self):
        hp = self.paperclip_home()
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser")
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.acl_calls(r.stdout, "grant")
        self.assertNotIn("setfacl", r.stdout, "every entry goes through the symlink-safe helper")
        tree = os.path.join(hp, ".paperclip/cli/installs/npm/2026.1012.0")
        for want in (("x", hp), ("x", f"{hp}/.claude"), ("r", f"{hp}/.claude/settings.json"), ("r", f"{hp}/.ssh/authorized_keys"),
                     ("r", f"{hp}/.bashrc"), ("R", f"{hp}/.claude/skills"), ("R", f"{hp}/.config/systemd/user"),
                     ("x", f"{hp}/.paperclip/instances/default/companies/c1/agents/a1/.claude"),
                     ("r", f"{hp}/.paperclip/instances/default/companies/c1/agents/a1/.claude/settings.json"),
                     ("x", f"{tree}/node_modules/@paperclipai/server/dist/routes"),
                     ("r", f"{tree}/node_modules/@paperclipai/server/dist/routes/agents.js")):
            self.assertIn(("grant", *want), calls)
        text = "\n".join(p for _, _, p in calls)
        for never in (".credentials.json", "id_ed25519", "secrets", "master.key", "chat.jsonl", "projects", ".bash_logout", "/etc"):
            self.assertNotIn(never, text)
        self.assertIn(".bash_logout (it is, or sits behind, a symlink)", r.stdout)
        self.assertEqual(len(calls), len(set(calls)), "each path once")
        kinds = [k for _, k, _ in calls]                                                       # traversal first, recursive trees last
        self.assertEqual(kinds, sorted(kinds, key="xrR".index))
        # the manifest: root-owned file in /etc/itsec, keyed by the tree as the collector reads it
        with open(self.p("etc/itsec/patch-manifest.json")) as f:
            manifest = json.load(f)
        self.assertEqual(len(manifest), 9)
        self.assertTrue(all(k.startswith(f"{hp}/.paperclip/cli/current/node_modules/") for k in manifest))
        self.assertIn(f"wrote {self.p('etc/itsec/patch-manifest.json')}: 9 files", r.stdout)
        # the record --uninstall works from lists every grant
        with open(self.p("etc/itsec/acl-paths")) as f:
            recorded = [l.rstrip("\n").split("\t") for l in f]
        self.assertEqual(len(recorded), len(calls))
        self.assertEqual({(k, p) for k, p in recorded}, {(k, p) for _, k, p in calls})
        # a re-run grants the same again and keeps the record the same
        again = self.install()
        self.assertEqual(sorted(self.acl_calls(again.stdout, "grant")), sorted(calls))
        with open(self.p("etc/itsec/acl-paths")) as f:
            self.assertEqual([l.rstrip("\n").split("\t") for l in f], recorded)

    def test_the_grants_are_recorded_before_the_first_one_is_applied(self):
        """A failure half way through the grants must not leave a grant that --uninstall does not know."""
        self.paperclip_home()
        cmd = ["bash", "-x", os.path.join(self.dist, "install-watchdog.sh"), "--prefix", self.root, "--paperclip", self.hook.url, "--watched-user", "pcuser"]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env={**os.environ, "SUDO_USER": ""})
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])
        lines = r.stdout.splitlines()
        record = next(i for i, l in enumerate(lines) if re.match(r"\++ mv -f \S+/acl-paths\.new \S+/etc/itsec/acl-paths$", l))
        first = next(i for i, l in enumerate(lines) if l.startswith("would run: python3 -I -B") and "itsec-acl" in l)
        self.assertLess(record, first)

    def test_uninstall_removes_exactly_the_recorded_entries_before_the_account_goes(self):
        hp = self.paperclip_home()
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser")
        granted = {p: k for _, k, p in self.acl_calls(r.stdout, "grant")}
        self.assertGreater(len(granted), 10)
        u = self.install("--uninstall")
        self.assertEqual(u.returncode, 0, u.stderr)
        removed = {p: k for _, k, p in self.acl_calls(u.stdout, "remove")}
        self.assertEqual(removed, granted)
        self.assertEqual(len(self.acl_calls(u.stdout)), len(granted), "nothing but removals")
        lines = u.stdout.splitlines()
        self.assertLess(max(i for i, l in enumerate(lines) if "itsec-acl" in l), lines.index("would run: userdel itsec"))
        self.assertIn(f"removed the read access of itsec from {len(granted)} watched path(s)", u.stdout)
        # a path that has disappeared, or became a symlink, is left alone; so is a recorded path that was never applied
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser")
        os.remove(os.path.join(hp, ".bashrc"))
        os.symlink("/etc", os.path.join(hp, ".bashrc"))
        shutil.rmtree(os.path.join(hp, ".claude", "skills"))
        with open(self.p("etc/itsec/acl-paths"), "a") as f:
            f.write(f"r\t{hp}/.claude/never-granted-and-missing\n")
        u = self.install("--uninstall")
        self.assertEqual(u.returncode, 0, u.stderr)
        text = "\n".join(p for _, _, p in self.acl_calls(u.stdout))
        self.assertNotIn(".bashrc", text)
        self.assertNotIn(".claude/skills", text)
        self.assertNotIn("never-granted", text)
        self.assertIn(f"{hp}/.claude/settings.json", text)

    def faulty_script(self):
        """A copy of the installer whose `run` also fails with $FAKE_RC for a command line containing $FAKE_RC_MATCH: in a --prefix
        install the helper never really runs, so this stands in for it exiting 1 or 2 on one path."""
        with open(os.path.join(self.dist, "install-watchdog.sh")) as f:
            text = f.read()
        old = 'run() { if [ -n "$PREFIX" ]; then echo "would run: $*"; else "$@"; fi; }'
        self.assertEqual(text.count(old), 1)
        text = text.replace(old, 'run() { if [ -n "$PREFIX" ]; then echo "would run: $*"; if [ -n "${FAKE_RC_MATCH:-}" ] && [[ "$*" == *"$FAKE_RC_MATCH"* ]]; '
                                 'then return "${FAKE_RC:-1}"; fi; else "$@"; fi; }')
        with open(os.path.join(self.dist, "install-watchdog-faulty.sh"), "w") as f:
            f.write(text)
        return "install-watchdog-faulty.sh"

    def test_a_refused_path_is_reported_and_the_install_goes_on_but_an_unexpected_failure_stops_it(self):
        hp = self.paperclip_home()
        script = self.faulty_script()
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser", script=script, env={"FAKE_RC_MATCH": f"grant r {hp}/.bashrc", "FAKE_RC": "2"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"no read access for {hp}/.bashrc (refused, see above)", r.stdout)
        self.assertIn("wrote ", r.stdout, "the manifest and the timers still follow")
        self.assertIn("would run: systemctl enable --now", r.stdout)
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser", script=script, env={"FAKE_RC_MATCH": f"grant r {hp}/.bashrc", "FAKE_RC": "1"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(f"could not give itsec read access to {hp}/.bashrc", r.stderr)
        self.assertIn(f"{hp}/.bashrc", self.read("etc/itsec/acl-paths").decode(), "recorded before the failure")

    def test_uninstall_reports_and_keeps_the_entries_it_could_not_remove(self):
        hp = self.paperclip_home()
        script = self.faulty_script()
        self.install("--paperclip", self.hook.url, "--watched-user", "pcuser")
        left = self.p("root/itsec-acl-paths.left")
        u = self.install("--uninstall", script=script, env={"FAKE_RC_MATCH": f"remove R {hp}/.claude/skills", "FAKE_RC": "2"})
        self.assertEqual(u.returncode, 0, u.stderr)
        self.assertIn(f"could not remove the read access of itsec from {hp}/.claude/skills", u.stdout)
        self.assertIn("NOT removed: itsec may still have read access on 1 path(s)", u.stdout)
        self.assertIn(f"  R\t{hp}/.claude/skills", u.stdout)
        self.assertIn(f"saved in {left}", u.stdout)
        self.assertNotIn("(paths: ", u.stdout)
        with open(left) as f:
            self.assertEqual(f.read(), f"R\t{hp}/.claude/skills\n")
        self.assertEqual(os.stat(left).st_mode & 0o777, 0o600, "root only")
        self.assertEqual(os.stat(os.path.dirname(left)).st_mode & 0o077, 0)
        self.assertFalse(os.path.exists(self.p("etc/itsec")), "the file lives outside the directory the uninstall deletes")
        self.assertTrue(os.path.exists(left))

    def test_uninstall_keeps_the_whole_list_when_the_helper_is_gone_and_merges_with_an_earlier_one(self):
        hp = self.paperclip_home()
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser")
        granted = {(k, p) for _, k, p in self.acl_calls(r.stdout, "grant")}
        os.remove(self.p("opt/itsec/bin/itsec-acl"))
        left = self.p("root/itsec-acl-paths.left")
        os.makedirs(os.path.dirname(left), exist_ok=True)
        with open(left, "w") as f:
            f.write("r\t/home/old/earlier\n")
        u = self.install("--uninstall")
        self.assertEqual(u.returncode, 0, u.stderr)
        self.assertIn("cannot remove the read access of itsec", u.stdout)
        self.assertIn(f"NOT removed: itsec may still have read access on {len(granted)} path(s)", u.stdout)
        with open(left) as f:
            kept = {tuple(l.rstrip("\n").split("\t")) for l in f}
        self.assertEqual(kept, granted | {("r", "/home/old/earlier")})
        self.assertEqual(os.stat(left).st_mode & 0o777, 0o600)

    def test_a_clean_uninstall_leaves_no_list_behind(self):
        self.paperclip_home()
        self.install("--paperclip", self.hook.url, "--watched-user", "pcuser")
        u = self.install("--uninstall")
        self.assertEqual(u.returncode, 0, u.stderr)
        self.assertNotIn("NOT removed", u.stdout)
        self.assertFalse(os.path.exists(self.p("root/itsec-acl-paths.left")))

    def test_the_manifest_generator_is_told_the_watched_uid(self):
        self.paperclip_home()
        cmd = ["bash", "-x", os.path.join(self.dist, "install-watchdog.sh"), "--prefix", self.root, "--paperclip", self.hook.url, "--watched-user", "pcuser"]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env={**os.environ, "SUDO_USER": ""})
        self.assertEqual(r.returncode, 0, r.stdout[-2000:])
        self.assertRegex(r.stdout, rf"itsec-make-manifest --uid {os.getuid()} --tree \S+ --out ")

    def test_missing_paperclip_tree_still_installs_and_says_what_to_do(self):
        os.makedirs(self.p("home/paperclip"))
        r = self.install("--paperclip", self.hook.url)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no Paperclip install found", r.stdout)
        self.assertIn("the patch manifest was NOT written", r.stdout)
        self.assertFalse(os.path.exists(self.p("etc/itsec/patch-manifest.json")))
        self.assertIn("run this installer again", r.stdout)
        # an unpatched tree is refused by the generator, the install goes on and an older manifest stays
        tree = os.path.join(self.p("home/paperclip"), ".paperclip/cli/installs/npm/1")
        self.write(os.path.join(tree, "node_modules/@paperclipai/server/dist/routes/agents.js"), "unpatched\n")
        os.symlink("installs/npm/1", os.path.join(self.p("home/paperclip"), ".paperclip/cli/current"))
        self.write(self.p("etc/itsec/patch-manifest.json"), "{}\n")
        r = self.install()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("the patch manifest was NOT written", r.stdout)
        self.assertEqual(self.read("etc/itsec/patch-manifest.json"), b"{}\n")

    def test_a_symlink_loop_at_the_paperclip_tree_does_not_stop_the_install(self):
        hp = self.paperclip_home()
        link = os.path.join(hp, ".paperclip/cli/current")
        os.remove(link)
        os.symlink("current", link)                                   # realpath -m fails on a loop (rc 1); under set -e that used to abort
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"cannot resolve {link} (a symlink loop?)", r.stdout)
        self.assertIn("the patch manifest was NOT written", r.stdout)
        self.assertFalse(os.path.exists(self.p("etc/itsec/patch-manifest.json")))
        calls = self.acl_calls(r.stdout, "grant")
        self.assertIn(("grant", "r", f"{hp}/.claude/settings.json"), calls, "the other watched paths still get their access")
        self.assertFalse([c for c in calls if "/cli/" in c[2]], "nothing is granted in the tree")
        self.assertIn("would run: systemctl enable --now itsec-collect.timer", r.stdout)       # the timers are still installed
        self.assertTrue(os.path.exists(self.p("etc/itsec/acl-paths")))

    def test_more_agent_settings_files_than_the_cap_are_refused_as_a_whole(self):
        hp = self.paperclip_home()
        for i in range(8):
            self.write(os.path.join(hp, f".paperclip/instances/default/companies/c1/agents/x{i}/.claude/settings.json"), "x\n")
        with open(os.path.join(self.dist, "install-watchdog.sh")) as f:
            src = f.read()
        with open(os.path.join(self.dist, "install-watchdog-cap.sh"), "w") as f:
            f.write(src.replace("AGENTS_MAX=500", "AGENTS_MAX=5"))
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser", script="install-watchdog-cap.sh")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("more than 5 of them", r.stdout)
        self.assertFalse([c for c in self.acl_calls(r.stdout, "grant") if "/agents/" in c[2]])
        self.assertIn("would run: systemctl enable --now", r.stdout)
        r = self.install("--paperclip", self.hook.url)                 # under the real cap: all nine are granted
        self.assertEqual(len([c for c in self.acl_calls(r.stdout, "grant") if c[1] == "r" and "/agents/" in c[2]]), 9)

    def test_a_huge_agents_directory_without_any_settings_file_is_refused_not_walked(self):
        hp = self.paperclip_home()
        for i in range(30):                                            # decoy agent directories: nothing to grant in any of them
            os.makedirs(os.path.join(hp, f".paperclip/instances/default/companies/c1/agents/x{i}/work/deep"))
        with open(os.path.join(self.dist, "install-watchdog.sh")) as f:
            src = f.read()
        self.assertIn("ENTRIES_MAX=20000", src)
        with open(os.path.join(self.dist, "install-watchdog-cap.sh"), "w") as f:
            f.write(src.replace("ENTRIES_MAX=20000", "ENTRIES_MAX=25"))
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser", script="install-watchdog-cap.sh")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("more than 25 directory entries", r.stdout)
        self.assertFalse([c for c in self.acl_calls(r.stdout, "grant") if "/agents/" in c[2]])
        self.assertIn("would run: systemctl enable --now", r.stdout)
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser")       # under the real cap: nothing to refuse
        self.assertNotIn("directory entries", r.stdout)

    def test_only_the_claude_directories_of_agents_are_entered(self):
        hp = self.paperclip_home()
        base = os.path.join(hp, ".paperclip/instances/default/companies")
        self.write(os.path.join(base, "c1/agents/a1/.claude/settings.json"), "x\n")
        self.write(os.path.join(base, "c1/agents/a1/.claude/settings.local.json"), "x\n")
        self.write(os.path.join(base, "c1/agents/a1/other/.claude/settings.json"), "x\n")        # too deep
        self.write(os.path.join(base, "c1/projects/p/agents/a/.claude/settings.json"), "x\n")    # not below companies/*/agents
        self.write(os.path.join(base, "c2/agents/a2/.claude/settings.txt"), "x\n")
        r = self.install("--paperclip", self.hook.url, "--watched-user", "pcuser")
        got = sorted(c[2] for c in self.acl_calls(r.stdout, "grant") if c[1] == "r" and "/companies/" in c[2])
        self.assertEqual([os.path.relpath(g, base) for g in got if g.startswith(base + "/c1/agents/a1")],
                         ["c1/agents/a1/.claude/settings.json", "c1/agents/a1/.claude/settings.local.json"])
        self.assertFalse([g for g in got if "/other/" in g or "/projects/" in g or g.endswith(".txt")])

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

    def test_the_weekly_lynis_timer_is_enabled_only_when_lynis_is_installed(self):
        r = self.install("--paperclip", self.hook.url)
        self.assertIn("would run: systemctl enable --now itsec-collect.timer itsec-report.timer itsec-lynis.timer", r.stdout)
        self.assertNotIn("lynis is not installed", r.stdout)
        # a PATH without lynis (skipped where lynis sits next to the tools the installer needs)
        keep = [d for d in os.environ["PATH"].split(os.pathsep) if not os.path.exists(os.path.join(d, "lynis"))]
        if shutil.which("lynis", path=os.pathsep.join(keep)) or not all(shutil.which(c, path=os.pathsep.join(keep)) for c in NEEDED_TOOLS):
            self.skipTest("cannot build a PATH without lynis that still has the installer's tools")
        self.root = os.path.join(self.tmp, f"root-nolynis-{self.n}")
        r = self.install("--paperclip", self.hook.url, env={"PATH": os.pathsep.join(keep)})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("would run: systemctl enable --now itsec-collect.timer itsec-report.timer\n", r.stdout)
        self.assertNotIn("enable --now itsec-collect.timer itsec-report.timer itsec-lynis.timer", r.stdout)
        self.assertIn("lynis is not installed, so the weekly audit timer stays off; after 'apt-get install lynis' run: sudo systemctl enable --now itsec-lynis.timer", r.stdout)

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
    def test_hermes_needs_node_where_the_wrapper_expects_it(self):
        r = self.install(script="install-hermes-wrapper.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("needs Node at /usr/local/bin/node", r.stderr)
        self.assertFalse(os.path.exists(self.p("usr/local/bin/hermes-sandbox")), "nothing is installed without it")
        self.write(self.p("usr/local/bin/node"), "#!/bin/sh\n")                 # present but not executable
        self.assertNotEqual(self.install(script="install-hermes-wrapper.sh").returncode, 0)
        os.chmod(self.p("usr/local/bin/node"), 0o755)
        self.assertEqual(self.install(script="install-hermes-wrapper.sh").returncode, 0)

    def test_hermes_install_mismatch_and_uninstall(self):
        self.write(self.p("usr/local/bin/node"), "#!/bin/sh\n")
        os.chmod(self.p("usr/local/bin/node"), 0o755)
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
