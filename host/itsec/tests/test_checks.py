import _bootstrap  # noqa: F401
import json
from pathlib import Path
import os
import tempfile
import time
import unittest

from helpers import make_cfg, FakeRun, write_chain, put, open_read, T0
from itsec import checks, sources
from itsec.core import State

SS1 = """Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
tcp LISTEN 0 4096 127.0.0.1:8790 0.0.0.0:*
udp UNCONN 0 0 127.0.0.54:53 0.0.0.0:*
udp UNCONN 0 0 0.0.0.0:40000 0.0.0.0:*
"""


def rules(fs):
    return {f["rule"]: f["severity"] for f in fs}


class Files(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.f = os.path.join(self.d, "authorized_keys")
        put(self.f, "ssh-ed25519 AAAA owner\n", "w")
        self.cfg = make_cfg(self.d, watch=[{"globs": [self.d + "/authorized_keys", self.d + "/sub"], "severity": "HIGH"}])

    def test_baseline_then_change_create_remove(self):
        st = State(self.d)
        self.assertEqual(checks.check_files(self.cfg, st, True, T0), [])
        self.assertEqual(checks.check_files(self.cfg, st, False, T0), [])        # unchanged
        put(self.f, "ssh-ed25519 BBBB attacker\n", "a")
        fs = checks.check_files(self.cfg, st, False, T0)
        self.assertEqual((fs[0]["severity"], fs[0]["rule"]), ("HIGH", "file-change"))
        self.assertEqual(checks.check_files(self.cfg, st, False, T0), [])        # reported once, state updated
        os.makedirs(self.d + "/sub")
        put(self.d + "/sub/x.service", "[Service]\n", "w")
        self.assertIn("created", checks.check_files(self.cfg, st, False, T0)[0]["title"])
        os.remove(self.f)
        self.assertIn("removed", checks.check_files(self.cfg, st, False, T0)[0]["title"])

    def test_unreadable_file_uses_stat_signature(self):
        sig = sources.file_signature(self.d + "/nonexistent")
        self.assertEqual(sig, "missing")
        os.chmod(self.f, 0)
        if os.access(self.f, os.R_OK):
            self.skipTest("running as root")
        self.assertTrue(sources.file_signature(self.f).startswith("stat:"))
        os.chmod(self.f, 0o600)


class Accounts(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.pw, self.gr = self.d + "/passwd", self.d + "/group"
        put(self.pw, "root:x:0:0::/root:/bin/bash\npaperclip:x:1000:1000::/home/paperclip:/bin/bash\n", "w")
        put(self.gr, "root:x:0:\nsudo:x:27:admin\npaperclip:x:1000:\n", "w")
        self.cfg, self.st = make_cfg(self.d), State(self.d)
        checks.check_accounts(self.cfg, self.st, True, T0, self.pw, self.gr)

    def test_new_user_and_group_and_priv_membership(self):
        put(self.pw, "evil:x:1001:1001::/home/evil:/bin/bash\n", "a")
        put(self.gr, "root:x:0:\nsudo:x:27:admin,paperclip\npaperclip:x:1000:\nhackers:x:1002:\n", "w")
        r = rules(checks.check_accounts(self.cfg, self.st, False, T0, self.pw, self.gr))
        self.assertEqual(r, {"new-user": "HIGH", "new-group": "MEDIUM", "group-membership": "HIGH"})
        self.assertEqual(checks.check_accounts(self.cfg, self.st, False, T0, self.pw, self.gr), [])

    def test_shell_change(self):
        put(self.pw, "root:x:0:0::/root:/bin/bash\npaperclip:x:1000:1000::/home/paperclip:/bin/zsh\n", "w")
        self.assertEqual(rules(checks.check_accounts(self.cfg, self.st, False, T0, self.pw, self.gr)), {"user-changed": "HIGH"})


class Ports(unittest.TestCase):
    def test_parse_ignores_ephemeral_udp(self):
        self.assertEqual(sources.parse_ss(SS1), ["tcp 0.0.0.0:22", "tcp 127.0.0.1:8790", "udp 127.0.0.54:53"])

    def test_new_listener_severity_by_exposure(self):
        d = tempfile.mkdtemp()
        cfg, st = make_cfg(d), State(d)
        self.assertEqual(checks.check_ports(cfg, st, True, T0, FakeRun({"ss": (0, SS1)})), [])
        more = SS1 + "tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:*\ntcp LISTEN 0 1 127.0.0.1:9999 0.0.0.0:*\n"
        fs = checks.check_ports(cfg, st, False, T0, FakeRun({"ss": (0, more)}))
        self.assertEqual({f["title"].split(": ")[1]: f["severity"] for f in fs},
                         {"tcp 0.0.0.0:4444": "HIGH", "tcp 127.0.0.1:9999": "MEDIUM"})
        self.assertEqual(checks.check_ports(cfg, st, False, T0, FakeRun({"ss": (0, more)})), [])

    def test_ss_failure_reported(self):
        d = tempfile.mkdtemp()
        fs = checks.check_ports(make_cfg(d), State(d), False, T0, FakeRun({"ss": (1, "")}))
        self.assertEqual(rules(fs), {"source-unreadable": "MEDIUM"})


class Processes(unittest.TestCase):
    def test_unexpected_process(self):
        d = tempfile.mkdtemp()
        ps = "paperclip node\npaperclip bash\npaperclip xmrig\nroot sshd\nother nc\n"
        fs = checks.check_processes(make_cfg(d), State(d), False, T0, FakeRun({"ps": (0, ps)}))
        self.assertEqual([(f["rule"], f["evidence"][0]) for f in fs], [("unexpected-process", "xmrig")])
        self.assertEqual(checks.check_processes(make_cfg(d), State(d), True, T0, FakeRun({"ps": (0, ps)})), [])


class Patches(unittest.TestCase):
    """in-process check against a root-owned manifest; nothing is executed."""
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.f1, self.f2 = self.d + "/agents.js", self.d + "/heartbeat.js"
        put(self.f1, "a\n// LOCAL-PATCH 0002\nb\n")
        put(self.f2, "x\n// LOCAL-PATCH 0003\n")
        self.cfg = make_cfg(self.d)
        self.write_manifest()

    def write_manifest(self, mode=0o644):
        import hashlib
        m = {p: {"sha256": hashlib.sha256(Path(p).read_bytes()).hexdigest(), "markers": [mk]}
             for p, mk in ((self.f1, "// LOCAL-PATCH 0002"), (self.f2, "// LOCAL-PATCH 0003"))}
        put(self.cfg["patch_manifest"], json.dumps(m))
        os.chmod(self.cfg["patch_manifest"], mode)

    def check(self):
        return checks.check_patches(self.cfg, State(self.d), False, T0)

    def test_intact_is_clean_and_nothing_runs(self):
        class Boom(FakeRun):
            def __call__(self, *a, **k):
                raise AssertionError("check_patches must not execute anything")
        self.assertEqual(checks.check_patches(self.cfg, State(self.d), False, T0, Boom({})), [])

    def test_hash_mismatch_is_high(self):
        put(self.f1, "a\n// LOCAL-PATCH 0002\nb tampered\n")
        self.assertEqual(rules(self.check()), {"patch-undone": "HIGH"})

    def test_missing_marker_is_high(self):
        put(self.f2, "x reverted\n")
        fs = self.check()
        self.assertEqual(rules(fs), {"patch-undone": "HIGH"})
        self.assertIn("missing_markers", " ".join(fs[0]["evidence"]))

    def test_missing_or_unreadable_file_is_medium_degraded_not_high(self):
        os.remove(self.f1)
        fs = self.check()
        self.assertEqual(rules(fs), {"watch-degraded": "MEDIUM"})
        self.assertIn("agents.js", " ".join(fs[0]["evidence"]))

    def test_missing_manifest_is_medium_degraded(self):
        os.remove(self.cfg["patch_manifest"])
        self.assertEqual(rules(self.check()), {"watch-degraded": "MEDIUM"})
        put(self.cfg["patch_manifest"], "{broken")
        self.assertEqual(rules(self.check()), {"watch-degraded": "MEDIUM"})

    def test_manifest_writable_by_others_or_wrong_owner_is_untrusted(self):
        self.write_manifest(mode=0o666)
        self.assertEqual(rules(self.check()), {"patch-manifest-untrusted": "HIGH"})
        self.write_manifest()
        self.cfg["patch_manifest_owner_uid"] = os.getuid() + 12345
        self.assertEqual(rules(self.check()), {"patch-manifest-untrusted": "HIGH"})

    def test_generator_script_output_is_accepted(self):
        import subprocess, sys
        out = self.d + "/gen.json"
        r = subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(__file__), "..", "bin", "itsec-make-manifest"),
                            "--out", out, "--target", f"{self.f1}=// LOCAL-PATCH 0002", "--target", f"{self.f2}=// LOCAL-PATCH 0003"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.cfg["patch_manifest"] = out
        os.chmod(out, 0o644)
        self.assertEqual(self.check(), [])
        r = subprocess.run([sys.executable, "-I", os.path.join(os.path.dirname(__file__), "..", "bin", "itsec-make-manifest"),
                            "--out", out + "2", "--target", f"{self.f1}=// LOCAL-PATCH 9999"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)                       # refuses to record an unpatched file


class PaperclipProcess(unittest.TestCase):
    """restart detection by process start time."""
    PS = "  1234 {lstart} paperclip node /home/paperclip/.paperclip/cli/current/bin/paperclipai run\n  99 Mon Jan  1 00:00:00 2026 root sshd\n"

    def ps(self, ts):
        return FakeRun({"ps": (0, self.PS.format(lstart=time.strftime("%a %b %e %H:%M:%S %Y", time.localtime(ts))))})

    def test_restart_detected_once_started_later_and_window_suppresses(self):
        d = tempfile.mkdtemp()
        cfg, st = make_cfg(d), State(d)
        self.assertEqual(checks.check_paperclip_process(cfg, st, True, T0, self.ps(T0 - 3600)), [])
        self.assertEqual(checks.check_paperclip_process(cfg, st, False, T0, self.ps(T0 - 3600)), [])      # same start: nothing
        fs = checks.check_paperclip_process(cfg, st, False, T0 + 900, self.ps(T0 + 600))
        self.assertEqual(rules(fs), {"paperclip-restart": "MEDIUM"})
        # a planned window silences it
        lo = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(T0 + 1000))
        hi = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(T0 + 2000))
        cfg["known_restart_windows"] = [[lo, hi]]
        self.assertEqual(checks.check_paperclip_process(cfg, st, False, T0 + 2100, self.ps(T0 + 1500)), [])


class DiskAndWatch(unittest.TestCase):
    def test_disk_free_thresholds(self):
        import types
        d = tempfile.mkdtemp()
        cfg = make_cfg(d, disk_paths=["/", "/var/log", "/x"])
        sv = {"/": 15, "/var/log": 5, "/x": 50}
        fs = checks.check_disk(cfg, State(d), False, T0, lambda p: types.SimpleNamespace(f_bavail=sv[p], f_blocks=100))
        self.assertEqual(sorted((f["severity"] for f in fs)), ["HIGH", "MEDIUM"])

    def test_unreachable_literal_watch_path_is_reported(self):
        if os.getuid() == 0:
            self.skipTest("root bypasses permissions")
        d = tempfile.mkdtemp()
        os.makedirs(d + "/closed/inner")
        put(d + "/closed/inner/f", "x")
        os.chmod(d + "/closed", 0)
        self.addCleanup(os.chmod, d + "/closed", 0o700)
        cfg = make_cfg(d, watch=[{"severity": "HIGH", "globs": [d + "/closed/inner/f", d + "/closed/*/g", d + "/absent"]}])
        fs = checks.check_files(cfg, State(d), True, T0)
        self.assertEqual([f["rule"] for f in fs], ["watch-unreadable", "watch-unreadable"])
        self.assertTrue(all(f["severity"] == "MEDIUM" for f in fs))

    def test_watch_exclude_skips_matching_files_only(self):
        d = tempfile.mkdtemp()
        os.makedirs(d + "/plugins/cache/p")
        os.makedirs(d + "/plugins/marketplaces/m")
        put(d + "/plugins/cache/p/x.js", "a", "w")
        put(d + "/plugins/marketplaces/m/y.json", "a", "w")
        put(d + "/plugins/known_marketplaces.json", "a", "w")
        cfg = make_cfg(d, watch=[{"severity": "HIGH", "globs": [d + "/plugins"],
                                  "exclude": [d + "/plugins/marketplaces/*/y.json", d + "/plugins/known_marketplaces.json"]}])
        got = sources.expand_watch(cfg)
        self.assertEqual(sorted(os.path.relpath(p, d) for p in got), ["plugins/cache/p/x.js"])

    def test_exclude_is_per_segment_and_never_hides_descendants(self):
        d = tempfile.mkdtemp()
        os.makedirs(d + "/synced/.bucket-x")
        put(d + "/synced/.bucket-x/SKILL.md", "a", "w"); put(d + "/synced/.bucket-y", "", "w")
        cfg = make_cfg(d, watch=[{"severity": "HIGH", "globs": [d + "/synced"], "exclude": [d + "/synced/.bucket-*"]}])
        self.assertEqual(sorted(os.path.relpath(p, d) for p in sources.expand_watch(cfg)), ["synced/.bucket-x/SKILL.md"])

    def test_newly_excluded_baseline_path_is_not_reported_removed(self):
        d = tempfile.mkdtemp()
        put(d + "/a", "1", "w"); put(d + "/churn", "1", "w")
        st = State(d)
        checks.check_files(make_cfg(d, watch=[{"severity": "HIGH", "globs": [d + "/a", d + "/churn"]}]), st, True, T0)
        cfg = make_cfg(d, watch=[{"severity": "HIGH", "globs": [d + "/a", d + "/churn"], "exclude": [d + "/churn"]}])
        self.assertEqual(checks.check_files(cfg, st, False, T0), [])

    def test_sudoers_d_change_is_high(self):
        d = tempfile.mkdtemp()
        os.makedirs(d + "/sudoers.d")
        put(d + "/sudoers.d/90-x", "admin ALL=(ALL) ALL\n")
        cfg = make_cfg(d, watch=[{"severity": "HIGH", "globs": [d + "/sudoers.d"]}])
        st = State(d)
        checks.check_files(cfg, st, True, T0)
        put(d + "/sudoers.d/90-x", "paperclip ALL=(ALL) NOPASSWD:ALL\n")
        put(d + "/sudoers.d/91-new", "x\n")
        fs = checks.check_files(cfg, st, False, T0)
        self.assertEqual({f["severity"] for f in fs}, {"HIGH"})
        self.assertEqual(len(fs), 2)


def rec(**kw):
    base = {"agent": "a1", "issue": "i1", "credential": "github-x", "reason": "r", "decision": "deny", "ceiling": "none",
            "time": "2026-10-13T06:00:00Z", "mode": "judge", "lease_end": None, "probabilities": None}
    base.update(kw)
    return base


class Vault(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.cfg = make_cfg(self.d)

    def run_vault(self, records, baseline=False, st=None, tamper=None):
        write_chain(self.cfg["vault_audit_log"], records, tamper)
        return checks.check_vault(self.cfg, st or State(self.d), baseline, T0)

    def test_each_rule(self):
        recs = [rec(ceiling="judge-lock"), rec(ceiling="never-grantable", credential="vaultd-judge.openrouter"),
                rec(ceiling="agent-locked"), rec(agent=None, ceiling="identity", unauthenticated_total=1),
                rec(agent=None, ceiling="bad-name"), rec(decision="backoff", ceiling="loop-guard"),
                rec(decision="backoff", ceiling="loop-guard-agent", credential="y"),
                rec(ceiling="unknown-agent", agent="zzz"), rec(ceiling="approval-mismatch"),
                {"admin": "unlock", "ok": True, "time": "2026-10-13T06:01:00Z"},
                rec(decision="grant", ceiling="ttl"), rec(decision="deny", ceiling="judge-deny")]
        fs = self.run_vault(recs)
        r = {}
        for f in fs:
            r.setdefault(f["rule"], []).append(f)
        sev = {k: v[0]["severity"] for k, v in r.items()}
        self.assertEqual(sev, {"vault-judge-lock": "HIGH", "vault-never-grantable": "HIGH", "vault-locked-agent-request": "MEDIUM",
                               "vault-identity-failure": "MEDIUM", "vault-loop-guard": "MEDIUM", "vault-unknown-agent": "MEDIUM",
                               "vault-approval-mismatch": "MEDIUM", "vault-admin": "INFO", "vault-stats": "INFO"})
        self.assertEqual(r["vault-identity-failure"][0]["count"], 2)
        self.assertEqual(len(r["vault-loop-guard"]), 2)                       # two different credentials
        self.assertIn("grants=1", r["vault-stats"][0]["evidence"][0])
        self.assertNotIn("vault-chain-broken", r)

    def test_incremental_offset(self):
        st = State(self.d)
        self.run_vault([rec(ceiling="judge-lock")], st=st)
        fs = checks.check_vault(self.cfg, st, False, T0)                       # nothing new
        self.assertEqual(fs, [])

    def test_chain_failure_is_high(self):
        def tamper(lines):
            lines[1]["reason"] = "edited"                                      # hash no longer matches
        fs = self.run_vault([rec(), rec(), rec()], tamper=tamper)
        self.assertEqual(rules(fs).get("vault-chain-broken"), "HIGH")

    def test_chain_deleted_record_is_high(self):
        def tamper(lines):
            del lines[1]
        fs = self.run_vault([rec(), rec(), rec()], tamper=tamper)
        self.assertEqual(rules(fs).get("vault-chain-broken"), "HIGH")

    def test_verify_agrees_with_vaultd_verifier(self):
        vdir = "$PKG/host/vault"
        if not os.path.isdir(vdir + "/vaultd"):
            self.skipTest("vaultd source not present")
        import importlib.util
        spec = importlib.util.spec_from_file_location("vaultd_audit", vdir + "/vaultd/audit.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        p = self.cfg["vault_audit_log"]
        write_chain(p, [rec(), rec(), rec()])
        self.assertTrue(mod.verify([p])[0] and checks.verify_chain([p])[0])
        write_chain(p, [rec(), rec(), rec()], lambda l: l[1].update(reason="edited"))
        self.assertFalse(mod.verify([p])[0] or checks.verify_chain([p])[0])

    def test_baseline_skips_records_but_still_verifies(self):
        self.assertEqual(self.run_vault([rec(ceiling="judge-lock")], baseline=True), [])
        def tamper(lines):
            lines[0]["agent"] = "x"
        fs = self.run_vault([rec()], baseline=True, tamper=tamper)
        self.assertEqual(rules(fs), {"vault-chain-broken": "HIGH"})

    def test_unparsable_line_is_medium(self):
        write_chain(self.cfg["vault_audit_log"], [rec()])
        put(self.cfg["vault_audit_log"], "{torn\n", "a")
        fs = checks.check_vault(self.cfg, State(self.d), False, T0)
        self.assertEqual(rules(fs).get("vault-unparsable"), "MEDIUM")

    def test_missing_log(self):
        fs = checks.check_vault(self.cfg, State(self.d), False, T0)
        self.assertEqual(rules(fs), {"source-unreadable": "MEDIUM"})

    def test_rotated_files_chain(self):
        # rotated oldest file + live file continuing the chain
        write_chain(self.d + "/audit-20261001.jsonl", [rec(), rec()])
        last = json.loads(open_read(self.d + "/audit-20261001.jsonl").splitlines()[-1])["hash"]
        e = dict(rec(), prev_hash=last)
        e["hash"] = checks._digest(e)
        put(self.cfg["vault_audit_log"], json.dumps(e, sort_keys=True) + "\n", "w")
        self.assertTrue(checks.verify_chain(sources.vault_files(self.cfg["vault_audit_log"]))[0])


if __name__ == "__main__":
    unittest.main()
