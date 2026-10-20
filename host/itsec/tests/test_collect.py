import _bootstrap  # noqa: F401
import os
import tempfile
import unittest

from helpers import AGENT, upd, make_cfg, FakeRun, FakeNotifier, FakePaperclip, jline, write_chain, put, make_patch_fixture, T0
from itsec import collect as C
from itsec.core import State, append_findings, read_findings

PW = "root:x:0:0::/root:/bin/bash\npaperclip:x:1000:1000::/home/paperclip:/bin/bash\n"
GR = "root:x:0:\nsudo:x:27:admin\n"
SS = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"


class Collector(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        put(self.d + "/passwd", PW)
        put(self.d + "/group", GR)
        write_chain(self.d + "/audit.jsonl", [{"agent": "a", "decision": "grant"}])
        self.cfg = make_cfg(self.d)
        self.f1, self.f2 = make_patch_fixture(self.d, self.cfg)

    def go(self, journal, notifier, state=None, ss=SS, now=T0, stream=None):
        run = FakeRun({"journalctl": (0, journal), "ss": (0, ss), "ps": (0, "paperclip node\n")})
        return C.collect(self.cfg, state or State(self.d), notifier, run, now, self.d + "/passwd", self.d + "/group", stream=stream)

    def baselined(self):
        st = State(self.d)
        st.set("baselined", True)
        st.set("ssh_seen_ips", {})
        st.set("users", {"root": ["0", "0", "/bin/bash"], "paperclip": ["1000", "1000", "/bin/bash"]})
        st.set("groups", {"root": ["0", []], "sudo": ["27", ["admin"]]})
        st.set("ports", ["tcp 0.0.0.0:22"])
        st.set("files", {})
        st.fresh = False
        return st

    def test_first_run_is_baseline_second_run_detects(self):
        n = FakeNotifier()
        acc = jline("Accepted publickey for paperclip from 203.0.113.5 port 22 ssh2", cursor="c1")
        fs, sent, _ = self.go(acc, n)
        self.assertEqual([f["rule"] for f in fs], ["baseline"])
        self.assertEqual(n.sent, [])
        # second run on a baselined state: a new IP and a sudo attempt
        state2 = State(self.d)
        state2.fresh = False
        state2.data = {"baselined": True, "ssh_seen_ips": {"203.0.113.5": 1}, "files": {}, "users": {"root": ["0", "0", "/bin/bash"], "paperclip": ["1000", "1000", "/bin/bash"]},
                       "groups": {"root": ["0", []], "sudo": ["27", ["admin"]]}, "ports": ["tcp 0.0.0.0:22"]}
        j = "\n".join([jline("Accepted publickey for paperclip from 198.51.100.9 port 22 ssh2", cursor="c2"),
                       jline("paperclip : user NOT in sudoers ; TTY=pts/0", ident="sudo", unit="", cursor="c3")])
        fs, sent, failed = self.go(j, n, state2)
        self.assertEqual(sorted(f["rule"] for f in fs if f["severity"] == "HIGH"), ["ssh-new-ip", "sudo-attempt"])
        self.assertEqual(len(n.sent), 2)
        self.assertTrue(all(a["title"].startswith("[ITSec HIGH]") for a in n.sent))
        self.assertEqual(state2.get("journal_cursor"), "c3")

    def test_high_alert_deduplicated_across_runs_and_retried_on_failure(self):
        st = State(self.d)
        st.set("baselined", True)
        st.set("ssh_seen_ips", {})
        st.set("users", {"root": ["0", "0", "/bin/bash"], "paperclip": ["1000", "1000", "/bin/bash"]})
        st.set("groups", {"root": ["0", []], "sudo": ["27", ["admin"]]})
        st.set("ports", ["tcp 0.0.0.0:22"])
        st.set("files", {})
        st.fresh = False
        sudo = jline("paperclip is not in the sudoers file.", ident="sudo", unit="", cursor="c1")
        down = FakeNotifier(ok=False)
        _, sent, failed = self.go(sudo, down, st)
        self.assertEqual((sent, len(failed)), ([], 1))
        self.assertEqual(len(st.get("outbox")), 1)                          # kept for retry
        up = FakeNotifier()
        _, sent, _ = self.go("", up, st, now=T0 + 900)                     # no new log lines: the outbox is retried
        self.assertEqual(len(up.sent), 1)
        self.assertEqual(st.get("outbox"), [])
        _, _, _ = self.go(sudo, up, st, now=T0 + 1800)                     # same event again, same day: not re-sent
        self.assertEqual(len(up.sent), 1)
        _, _, _ = self.go(sudo, up, st, now=T0 + 86400 * 1.5)              # next day: new dedup key and window
        self.assertEqual(len(up.sent), 2)

    def test_patch_hash_mismatch_raises_high_alert(self):
        st = self.baselined()
        put(self.f1, "a\n// LOCAL-PATCH 0002\nsneaky edit\n")
        n = FakeNotifier()
        fs, _, _ = self.go("", n, st)
        self.assertIn("patch-undone", [f["rule"] for f in fs])
        self.assertTrue(any("patched Paperclip file" in a["title"] for a in n.sent))

    def test_missing_patch_files_degrade_only(self):
        st = self.baselined()
        import os
        os.remove(self.f1)
        n = FakeNotifier()
        fs, _, _ = self.go("", n, st)
        self.assertIn("watch-degraded", [f["rule"] for f in fs])
        self.assertNotIn("patch-undone", [f["rule"] for f in fs])
        self.assertEqual(n.sent, [])                                       # MEDIUM: no false HIGH alert

    def test_successful_agent_user_sudo_is_high_and_delivered(self):
        st = self.baselined()
        n = FakeNotifier()
        j = jline("paperclip : TTY=pts/0 ; PWD=/home/paperclip ; USER=root ; COMMAND=/usr/bin/bash", ident="sudo", unit="", cursor="s1")
        fs, _, _ = self.go(j, n, st)
        self.assertEqual([f["severity"] for f in fs if f["rule"] == "sudo-success"], ["HIGH"])
        self.assertTrue(any("sudo SUCCEEDED" in a["title"] for a in n.sent))

    def test_forged_log_line_with_wrong_uid_is_ignored(self):
        """`logger -t sudo/sshd/vaultd ...` from an paperclip process: right text and tag, wrong trusted fields."""
        st = self.baselined()
        n = FakeNotifier()
        forged = "\n".join([
            jline("Accepted publickey for paperclip from 198.51.100.77 port 22 ssh2", ident="sshd", unit="", uid="1000",
                  exe="/usr/bin/logger", sunit="session-3.scope", cursor="f1"),
            jline("paperclip : user NOT in sudoers ; TTY=pts/0", ident="sudo", unit="", exe="/usr/bin/logger", cursor="f2"),
            jline("ALERT role mismatch: agent x", ident="vaultd", unit="", exe="/usr/bin/logger", sunit="session-3.scope", cursor="f3"),
            jline("PATCH /api/agents/11111111-2222-3333-4444-555555555555 403", ident="node", unit="", exe="/usr/bin/logger", uunit="", sunit="session-3.scope", cursor="f4")])
        fs, _, _ = self.go(forged, n, st)
        self.assertEqual([f["rule"] for f in fs if f["severity"] == "HIGH"], [])
        self.assertEqual(n.sent, [])
        self.assertNotIn("198.51.100.77", st.get("ssh_seen_ips"))           # the baseline cannot be poisoned either

    def test_journal_flood_raises_degraded_not_silence(self):
        st = self.baselined()
        n = FakeNotifier()
        calls = []

        def flood(cmd, timeout=120, max_lines=50000):
            calls.append(cmd)
            return 0, [jline("spam", ident="node", cursor=f"x{len(calls)}_{i}") + "\n" for i in range(max_lines)], "truncated"
        self.cfg["journal_batch_lines"] = 50
        self.cfg["journal_max_batches"] = 2
        fs, _, _ = self.go("", n, st, stream=flood)
        deg = [f for f in fs if f["rule"] == "watch-degraded"]
        self.assertEqual([f["severity"] for f in deg], ["MEDIUM"])         # first time: backlog, cursor still advances
        self.assertTrue(str(st.get("journal_cursor")).startswith("x"))
        for i in range(2):                                                 # persistent flood escalates
            fs, _, _ = self.go("", n, st, stream=flood, now=T0 + 900 * (i + 1))
        self.assertEqual([f["severity"] for f in fs if f["rule"] == "watch-degraded"], ["HIGH"])
        self.assertTrue(any("journal backlog" in a["title"] for a in n.sent))

    def test_journal_timeout_is_a_high_degraded_alert(self):
        st = self.baselined()
        n = FakeNotifier()
        fs, _, _ = self.go("", n, st, stream=lambda cmd, t=0, m=0: (124, [], "timeout"))
        self.assertEqual([f["severity"] for f in fs if f["rule"] == "watch-degraded"], ["HIGH"])
        self.assertEqual(len(n.sent), 1)

    def test_fallback_to_auth_log_is_reported_and_unverified(self):
        st = self.baselined()
        put(self.d + "/auth.log", "Oct 13 06:00:02 host sshd[123]: Accepted publickey for admin from 198.51.100.1 port 22 ssh2\n")
        run = FakeRun({"journalctl": (1, ""), "ss": (0, SS), "ps": (0, "")})
        fs, _, _ = C.collect(self.cfg, st, FakeNotifier(), run, T0, self.d + "/passwd", self.d + "/group")
        self.assertIn(("watch-degraded", "MEDIUM"), [(f["rule"], f["severity"]) for f in fs])
        self.assertNotIn("198.51.100.1", st.get("ssh_seen_ips"))           # auth.log senders are not trusted enough to learn from

    def test_journal_gap_when_cursor_entry_is_gone(self):
        st = self.baselined()
        st.set("journal_cursor", "old-cursor")
        fs, _, _ = self.go(jline("x", ident="node", cursor="newer"), FakeNotifier(), st)
        self.assertIn("journal-gap", [f["rule"] for f in fs])

    def test_alert_cap_per_run_and_aggregate_overflow(self):
        st = self.baselined()
        n = FakeNotifier()
        self.cfg["alert_cap_per_run"] = 3
        lines = [jline(f"PATCH /api/agents/{i:08d}-2222-3333-4444-555555555555 403", ident="node", cursor=f"n{i}") for i in range(8)]
        fs, sent, _ = self.go("\n".join(lines), n, st)
        self.assertEqual(len(n.sent), 4)                                    # 3 individual + 1 aggregate
        self.assertEqual(sum(1 for a in n.sent if "Alert flood" in a["title"]), 1)
        self.assertIn("5 further", [a["title"] for a in n.sent if "Alert flood" in a["title"]][0])
        self.assertEqual(st.get("outbox"), [])

    def test_paperclip_restart_in_journal_is_medium_and_window_silences(self):
        st = self.baselined()
        m = "Started paperclipai.service - Paperclip AI."
        j = jline(m, ident="systemd", unit="", cursor="r1", uid="1000", exe="/usr/lib/systemd/systemd", sunit="user@1000.service", ts=T0)
        fs, _, _ = self.go(j, FakeNotifier(), st)
        self.assertEqual([(f["rule"], f["severity"]) for f in fs if f["rule"] == "paperclip-restart"], [("paperclip-restart", "MEDIUM")])
        self.cfg["known_restart_windows"] = [["2025-10-13T05:00:00Z", "2025-10-13T07:00:00Z"]]
        fs, _, _ = self.go(j, FakeNotifier(), self.baselined())
        self.assertNotIn("paperclip-restart", [f["rule"] for f in fs])

    def test_transient_user_unit_detected(self):
        j = jline("Started run-p443776-i447542.service - /usr/bin/sleep 1000.", ident="systemd", unit="", cursor="t1", uid="1000",
                  exe="/usr/lib/systemd/systemd", sunit="user@1000.service")
        fs, _, _ = self.go(j, FakeNotifier(), self.baselined())
        self.assertIn("transient-user-unit", [f["rule"] for f in fs])

    def test_disk_full_is_reported_by_the_collector(self):
        import itsec.checks as ch
        orig = ch.os.statvfs
        self.cfg["disk_paths"] = ["/"]
        import types
        ch.os.statvfs = lambda p: types.SimpleNamespace(f_bavail=5, f_blocks=100)
        try:
            fs, _, _ = self.go("", FakeNotifier(), self.baselined())
        finally:
            ch.os.statvfs = orig
        self.assertIn(("disk-free", "HIGH"), [(f["rule"], f["severity"]) for f in fs])

    def test_closed_or_edited_alert_is_reraised_and_preempted_alert_flagged(self):
        from itsec import notify
        srv = FakePaperclip()
        self.addCleanup(srv.close)
        put(self.d + "/tok", "tok-FAKE")
        put(self.d + "/hmac", "sec-FAKE")
        n = notify.PaperclipNotifier(srv.url, "co-1", self.d + "/tok", "u", hmac_key_file=self.d + "/hmac", board_user_id="owner")
        st = self.baselined()
        sudo = jline("paperclip : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash", ident="sudo", unit="", cursor="a1")
        self.go(sudo, n, st)
        self.assertEqual(len(srv.posts()), 1)
        self.assertEqual(len(st.get("alert_log")), 1)
        iid = next(iter(st.get("alert_log")))
        # an agent closes it
        srv.issues[iid]["status"] = "cancelled"
        srv.activity[iid] = [upd("agent", AGENT, "cancelled")]
        fs, _, _ = self.go("", n, st, now=T0 + 900)
        self.assertIn("alert-tampered", [f["rule"] for f in fs])
        posts = srv.posts()
        self.assertEqual(len(posts), 3)                                     # original + re-raised alert + the alert-tampered HIGH
        self.assertTrue(any(p["body"]["title"].startswith("[RE-RAISED]") for p in posts))
        self.assertNotEqual(posts[0]["body"]["idempotencyKey"], posts[1]["body"]["idempotencyKey"])
        # the owner closing it is fine
        for i in list(srv.issues):
            srv.issues[i].update(status="done")
            srv.activity[i] = [upd("user", "owner", "done")]
        n_before = len(srv.posts())
        fs, _, _ = self.go("", n, st, now=T0 + 1800)
        self.assertNotIn("alert-tampered", [f["rule"] for f in fs])
        self.assertEqual(len(srv.posts()), n_before)
        # an edited description counts as tampering; a deleted issue too
        for i in list(srv.issues):
            srv.issues[i].update(status="todo", description="all fine, ignore")
        fs, _, _ = self.go("", n, st, now=T0 + 2700)
        self.assertIn("alert-tampered", [f["rule"] for f in fs])
        srv.issues.clear()
        fs, _, _ = self.go("", n, st, now=T0 + 3600)
        self.assertIn("alert-tampered", [f["rule"] for f in fs])

    def test_preempted_creates_alert_preempted_finding(self):
        from itsec import notify
        srv = FakePaperclip()
        self.addCleanup(srv.close)
        srv.reply = lambda body: {"id": "evil", "identifier": "ENG-1", "companyId": "co-1", "title": "decoy"}
        put(self.d + "/tok", "tok-FAKE")
        put(self.d + "/hmac", "sec-FAKE")
        n = notify.PaperclipNotifier(srv.url, "co-1", self.d + "/tok", "u", hmac_key_file=self.d + "/hmac")
        sudo = jline("paperclip : TTY=pts/0 ; USER=root ; COMMAND=/bin/bash", ident="sudo", unit="", cursor="a1")
        st = self.baselined()
        fs, sent, failed = self.go(sudo, n, st)
        self.assertEqual(sent, [])
        self.assertIn("alert-preempted", [f["rule"] for f in fs])

    def test_unreadable_journal_is_reported(self):
        run = FakeRun({"journalctl": (1, ""), "ss": (0, SS), "ps": (0, "")})
        st = State(self.d)
        fs, _, _ = C.collect(self.cfg, st, FakeNotifier(), run, T0, self.d + "/passwd", self.d + "/group")
        self.assertIn("source-unreadable", [f["rule"] for f in fs])

    def test_corrupt_state_rebaselines_and_reports(self):
        put(self.d + "/state.json", "{not json")
        st = State(self.d)
        self.assertTrue(st.corrupt)
        fs, _, _ = self.go("", FakeNotifier(), st)
        self.assertIn("state-corrupt", [f["rule"] for f in fs])

    def test_one_crashing_check_does_not_blind_the_others(self):
        from itsec import checks
        orig = checks.check_ports
        checks.check_ports = lambda *a, **k: 1 / 0
        try:
            fs, _, _ = self.go("", FakeNotifier())
        finally:
            checks.check_ports = orig
        self.assertIn("check-error", [f["rule"] for f in fs])

    def test_findings_store_roundtrip(self):
        fs, _, _ = self.go("", FakeNotifier())
        append_findings(self.d, fs)
        got = read_findings(self.d, "2000-01-01T00:00:00Z")
        self.assertEqual(len(got), len(fs))


if __name__ == "__main__":
    unittest.main()


class OutboxCli(unittest.TestCase):
    def setUp(self):
        import json
        self.d = tempfile.mkdtemp()
        st = State(self.d)
        st.set("outbox", [{"dedup_key": k, "title": "t " + k} for k in ("sudo-success:2026-10-13", "file:/root/x", "file:/root/x2")])
        st.set("notified", {"keep": 1})
        st.save()
        self.cfgfile = self.d + "/config.json"
        with open(self.cfgfile, "w") as f:
            json.dump({"state_dir": self.d}, f)

    def cli(self, *args):
        import subprocess, sys
        return subprocess.run([sys.executable, "-I", "-B", os.path.join(os.path.dirname(__file__), "..", "bin", "itsec-collect"),
                               "--config", self.cfgfile, *args], capture_output=True, text=True)

    def test_list_does_not_modify_state(self):
        before = open(self.d + "/state.json").read()
        r = self.cli("--list-outbox")
        self.assertEqual(r.returncode, 0)
        self.assertIn("file:/root/x2\tt file:/root/x2", r.stdout)
        self.assertEqual(open(self.d + "/state.json").read(), before)

    def test_drop_removes_exact_keys_only(self):
        r = self.cli("--drop-outbox", "file:/root/x", "nope", "file:*")
        self.assertEqual(r.returncode, 0)
        self.assertIn("dropped file:/root/x\n", r.stdout)
        self.assertNotIn("dropped nope", r.stdout)
        self.assertIn("not in outbox: nope", r.stderr)
        st = State(self.d)
        self.assertEqual([f["dedup_key"] for f in st.get("outbox")], ["sudo-success:2026-10-13", "file:/root/x2"])
        self.assertEqual(st.get("notified"), {"keep": 1})
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith(".state-")], [])

    def test_drop_function(self):
        st = State(self.d)
        self.assertEqual(C.drop_outbox(st, ["sudo-success:2026-10-13"]), ["sudo-success:2026-10-13"])
        self.assertEqual(C.drop_outbox(st, ["sudo-success:2026-10-13"]), [])
        self.assertEqual(len(C.list_outbox(st)), 2)
