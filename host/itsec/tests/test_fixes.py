"""One or more tests per hardening finding that the other test files do not already cover."""
import _bootstrap  # noqa: F401
import json
import os
import re
import sys
import tempfile
import unittest

from helpers import make_cfg, ev, jline, put, T0, FakeNotifier
from itsec import core, logrules, report as R, sources, lynis, checks
from itsec.core import State, make_finding

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def run(events, d, **over):
    cfg = make_cfg(d, **over)
    rules = logrules.load_rules(watched_user=cfg["watched_user"], cfg=cfg)
    return logrules.run_log_rules(events, rules, cfg, State(d), False, T0)


def rd(*p):
    with open(os.path.join(ROOT, *p)) as f:
        return f.read()


class Y1_NoExecutionUnderHome(unittest.TestCase):
    def test_no_apply_check_cmd_and_nothing_under_home_in_config_or_code(self):
        self.assertNotIn("apply_check_cmd", core.DEFAULT_CONFIG)
        self.assertNotIn("apply_check_cmd", json.loads(rd("config.example.json")))
        import inspect
        src = inspect.getsource(checks.check_patches)
        for bad in ("run(", "subprocess", "Popen", "apply.sh --check"):
            self.assertNotIn(bad, src.split('"""')[2])             # the code after the docstring never executes anything

    def test_manifest_install_step_documented(self):
        self.assertIn("itsec-make-manifest", rd("INSTALL.md"))
        self.assertIn("/etc/itsec/patch-manifest.json", rd("INSTALL.md"))


class Y2_SuAndSudo(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def test_successful_sudo_both_message_forms(self):
        for m in ["paperclip : TTY=pts/0 ; PWD=/home/paperclip ; USER=root ; COMMAND=/usr/bin/ls",
                  "pam_unix(sudo:session): session opened for user root(uid=0) by paperclip(uid=1000)"]:
            fs = run([ev(m, ident="sudo")], self.d)
            self.assertEqual([f["severity"] for f in fs if f["rule"] == "sudo-success"], ["HIGH"], m)

    def test_sudo_by_admin_is_not_flagged(self):
        fs = run([ev("admin : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls", ident="sudo"),
                  ev("pam_unix(sudo:session): session opened for user root(uid=0) by admin(uid=1001)", ident="sudo")], self.d)
        self.assertEqual([f for f in fs if f["rule"].startswith("sudo")], [])

    def test_su_by_agent_user_is_high(self):
        fs = run([ev("pam_unix(su:auth): authentication failure; logname=paperclip uid=1000 euid=0 tty=/dev/pts/0 ruser=paperclip rhost=  user=root", ident="su"),
                  ev("pam_unix(su-l:session): session opened for user root(uid=0) by paperclip(uid=1000)", ident="su")], self.d)
        f = [f for f in fs if f["rule"] == "su-attempt"]
        self.assertEqual((f[0]["severity"], f[0]["count"]), ("HIGH", 2))

    def test_new_sudo_rs_denial_wording(self):
        for m in ["User paperclip is not allowed to run sudo on host", "Sorry, user paperclip is not allowed to execute '/bin/ls' as root on host"]:
            fs = run([ev(m, ident="sudo")], self.d)
            self.assertEqual(len([f for f in fs if f["rule"] == "sudo-attempt"]), 1, m)


class Y3_Url403(unittest.TestCase):
    UUID = "00000000-0000-0000-0000-0000000000a2"

    def test_both_url_forms_with_pino_byte_array_and_colour_codes(self):
        d = tempfile.mkdtemp()
        for url in (f"PATCH /api/agents/{self.UUID} 403", f"PATCH /agents/{self.UUID} 403",
                    f"POST /agents/{self.UUID}/config-revisions/abc-1/rollback 403"):
            text = f"[06:00:01] \x1b[33mWARN\x1b[39m: \x1b[36m{url}\x1b[39m \x1b[90m{{\"x\":1}}\x1b[39m"
            line = json.dumps({"MESSAGE": list(text.encode()), "_SYSTEMD_USER_UNIT": "paperclipai.service", "_UID": "1000",
                               "_EXE": "/usr/bin/node", "__REALTIME_TIMESTAMP": str(int(T0 * 1e6)), "__CURSOR": "c"})
            evs, _ = sources.parse_journal_json(line)
            fs = run(evs, d)
            self.assertEqual([f["rule"] for f in fs if f["severity"] == "HIGH"], ["agent-selfconfig-403"], url)
        for url in (f"GET /agents/{self.UUID}/instructions-bundle/revisions 404", f"POST /agents/{self.UUID}/wakeup 403",
                    f"PATCH /issues/{self.UUID} 403"):
            self.assertEqual([f for f in run([ev(url, ident="node")], d) if f["rule"] == "agent-selfconfig-403"], [], url)


class Y4_TrustedFields(unittest.TestCase):
    def test_parse_keeps_trusted_fields_not_the_syslog_tag(self):
        evs, _ = sources.parse_journal_json(jline("m", ident="sshd", unit="", uid="1000", exe="/usr/bin/logger", sunit=""))
        self.assertEqual((evs[0]["uid"], evs[0]["exe"]), ("1000", "/usr/bin/logger"))
        self.assertEqual(evs[0]["sunit"], "")

    def test_forged_sshd_line_cannot_raise_or_poison(self):
        d = tempfile.mkdtemp()
        forged = ev("Accepted publickey for paperclip from 198.51.100.50 port 22 ssh2", ident="sshd", uid="1000", sunit="", exe="/usr/bin/logger")
        cfg = make_cfg(d)
        st = State(d)
        fs = logrules.run_log_rules([forged], logrules.load_rules(cfg=cfg), cfg, st, True, T0)       # baseline: must not learn it
        self.assertEqual(st.get("ssh_seen_ips"), {})
        fs = logrules.run_log_rules([forged], logrules.load_rules(cfg=cfg), cfg, st, False, T0)
        self.assertEqual(fs, [])

    def test_vault_uid_is_enforced_when_configured(self):
        d = tempfile.mkdtemp()
        good = ev("ALERT role mismatch: x", ident="vaultd")
        bad = ev("ALERT role mismatch: x", ident="vaultd", uid="1000")
        self.assertEqual(len(run([good], d, vault_uid="998")), 1)
        self.assertEqual(run([bad], d, vault_uid="998"), [])

    def test_ufw_requires_kernel_transport(self):
        d = tempfile.mkdtemp()
        m = "[UFW BLOCK] IN=eth0 SRC=198.51.100.7 DST=10.0.0.2 PROTO=TCP SPT=1 DPT=23"
        self.assertEqual([f["rule"] for f in run([ev(m, ident="kernel")], d)], ["ufw-blocks"])
        self.assertEqual(run([ev(m, ident="kernel", transport="syslog")], d), [])


class Y5_StreamedFilteredJournal(unittest.TestCase):
    def test_command_is_filtered_and_has_cursor_and_no_syslog_identifier(self):
        d = tempfile.mkdtemp()
        seen = []

        def fake(cmd, timeout=0, max_lines=0):
            seen.append(cmd)
            return 0, [], "ok"
        st = State(d)
        sources.read_journal(make_cfg(d), st, fake)
        self.assertIn("--since", seen[0])
        self.assertIn("_SYSTEMD_UNIT=ssh.service", seen[0])
        self.assertIn("+", seen[0])
        self.assertFalse(any("SYSLOG_IDENTIFIER" in a for a in seen[0]))
        st.set("journal_cursor", "CUR")
        seen.clear()
        sources.read_journal(make_cfg(d), st, fake)
        self.assertIn("--after-cursor", seen[1])

    def test_real_stream_cmd_truncates_and_times_out(self):
        rc, lines, status = sources.stream_cmd([sys.executable, "-I", "-c", "import sys\nfor i in range(100000): print(i)"], 20, 10)
        self.assertEqual((status, len(lines)), ("truncated", 10))
        rc, lines, status = sources.stream_cmd([sys.executable, "-I", "-c", "import time; print('x', flush=True); time.sleep(30)"], 1, 100)
        self.assertEqual(status, "timeout")
        self.assertEqual(lines, ["x\n"])
        self.assertEqual(sources.stream_cmd(["/nonexistent-binary"], 5, 5)[2], "error")


class Y6_AclDocs(unittest.TestCase):
    def test_install_step_4_has_installs_dirs_and_no_hooks_chain(self):
        t = rd("INSTALL.md")
        self.assertIn(".paperclip/cli/installs/npm", t)
        self.assertNotIn("-R -m u:itsec:rX /home/paperclip/.claude/hooks", t)
        self.assertNotIn(".claude-agents", rd("config.example.json"))


class Y7_Notifier(unittest.TestCase):
    def test_config_example_has_optional_separate_company_keys_unset(self):
        p = json.loads(rd("config.example.json"))["paperclip"]
        for k in ("alert_company_id", "alert_token_file", "board_user_id"):
            self.assertEqual(p[k], "")
        self.assertIn("Where the alert issues live", rd("INSTALL.md"))
        self.assertIn("BotNotifier", rd("README.md"))


class Y8_Persistence(unittest.TestCase):
    def test_watch_list_has_persistence_paths(self):
        g = " ".join(x for w in json.loads(rd("config.example.json"))["watch"] for x in w["globs"])
        for needle in ("/.bashrc", "/.local/bin", "/.config/environment.d", "/etc/pam.d", "/etc/ld.so.preload", "/.ssh/rc"):
            self.assertIn(needle, g)


class Y9_Fail2ban(unittest.TestCase):
    def test_logtarget_is_journal_and_rule_matches_journal_line(self):
        self.assertIn("logtarget = SYSTEMD-JOURNAL", rd("fail2ban", "fail2ban.local"))
        fs = run([ev("2026-10-13 06:00:00,1 fail2ban.actions [1]: NOTICE  [sshd] Ban 203.0.113.9", ident="fail2ban-server")], tempfile.mkdtemp())
        self.assertEqual(fs[0]["rule"], "fail2ban-ban")
        t = rd("INSTALL.md")
        self.assertIn("fail2ban-regex \"systemd-journal[journalmatch='_SYSTEMD_UNIT=ssh.service']\" sshd", t)
        self.assertIn("sudo journalctl -u ssh.service", t)


class Y10_Units(unittest.TestCase):
    def test_state_directory_mode_and_no_duplicate(self):
        for n in ("collect", "lynis", "report"):
            t = rd("systemd", f"itsec-{n}.service")
            self.assertIn("StateDirectoryMode=0700", t, n)
            self.assertEqual(len(re.findall(r"^StateDirectory=", t, re.M)), 1, n)

    def test_collect_unit_has_no_home_exec_and_gets_the_secret(self):
        t = rd("systemd", "itsec-collect.service")
        self.assertIn("idempotency-secret", t)
        self.assertNotIn("/home/paperclip/setup", t)


class Y11_ReportMarkdown(unittest.TestCase):
    def test_title_is_inline_code_and_ai_links_are_stripped(self):
        row = {"severity": "HIGH", "rule": "x", "title": "[click](http://evil) **bold** `tick`", "count": 1, "first": "a", "last": "b", "evidence": []}
        body = R.deterministic_report([row], 0, "w")
        self.assertIn("- `[click](http://evil) **bold** 'tick'`", body)
        out = R.sanitise_ai("see [report](http://evil.example/x) ![p](http://evil.example/p.png) <http://e.x> agent://abc ```")
        self.assertNotIn("http://evil", out)
        self.assertNotIn("agent://", out)
        self.assertNotIn("```", out)


class Y12_DayInKey(unittest.TestCase):
    def test_collect_sets_day_on_alerts(self):
        from itsec import collect as C
        st = State(tempfile.mkdtemp())
        n = FakeNotifier()
        f = make_finding("x", "HIGH", "t", "s", [], "k", T0)
        C.deliver(st, n, [f], make_cfg(st.dir), T0)
        self.assertEqual(n.sent[0]["day"], "2025-10-13")


class Y13_ClaudeBinary(unittest.TestCase):
    def test_autoupdater_off_and_root_install_documented(self):
        self.assertIn("DISABLE_AUTOUPDATER=1", rd("systemd", "itsec-report.service"))
        self.assertIn("root-owned", rd("INSTALL.md"))


class Y14_Lynis(unittest.TestCase):
    def test_consume_mode_parses_root_report_without_running_lynis(self):
        d = tempfile.mkdtemp()
        os.makedirs(d + "/lynis")
        put(d + "/lynis/report-new.dat", "hardening_index=70\nwarning[]=w1\n")
        cfg = make_cfg(d, lynis_consume_root_report=True)

        def boom(*a, **k):
            raise AssertionError("must not run lynis")
        fs = lynis.run_lynis(cfg, boom, T0)
        self.assertEqual(fs[0]["rule"], "lynis-baseline")
        self.assertIn("User=root", rd("systemd", "itsec-lynis-root.service"))


class Y15_Misc(unittest.TestCase):
    def test_ansi_debris_stripped_from_evidence(self):
        self.assertEqual(core.clean("\x1b[33mWARN\x1b[39m: x"), "WARN: x")

    def test_docs_name_the_right_files(self):
        self.assertIn("logrules.py", json.loads(rd("itsec", "rules.json"))["_doc"])
        self.assertNotRegex(rd("itsec", "rules.json"), r"(?<!log)rules\.py")


class Retention(unittest.TestCase):
    def test_findings_older_than_retention_are_pruned(self):
        d = tempfile.mkdtemp()
        os.makedirs(core.findings_dir(d))
        for name in ("2025-07-01", "2025-07-14", "2025-07-15", "2025-10-13"):
            put(os.path.join(core.findings_dir(d), name + ".jsonl"), "{}\n")
        put(os.path.join(core.findings_dir(d), "notes.txt"), "keep")
        now = T0                                                    # 2025-10-13
        self.assertEqual(core.prune_findings(d, 90, now), 2)        # cutoff 2025-07-15: 07-01 and 07-14 go, 07-15 stays
        self.assertEqual(sorted(os.listdir(core.findings_dir(d))), ["2025-07-15.jsonl", "2025-10-13.jsonl", "notes.txt"])
        self.assertEqual(core.prune_findings(d, 0, now), 0)         # 0 = keep forever
        self.assertEqual(core.prune_findings(d + "/nope", 90, now), 0)

    def test_config_key_default_90_and_collector_calls_prune(self):
        self.assertEqual(core.DEFAULT_CONFIG["findings_retention_days"], 90)
        self.assertEqual(json.loads(rd("config.example.json"))["findings_retention_days"], 90)
        self.assertIn("prune_findings", rd("bin", "itsec-collect"))

    def _chain(self, n):
        recs, prev = [], "0" * 64
        for i in range(n):
            e = {"event": "e", "i": i, "prev_hash": prev}
            e["hash"] = checks._digest(e)
            prev = e["hash"]
            recs.append(json.dumps(e) + "\n")
        return recs

    def _gz_setup(self, rotated_prev_ok=True):
        import gzip
        d = tempfile.mkdtemp()
        r = self._chain(3)
        with gzip.open(d + "/audit-2026-08-01T003000Z.jsonl.gz", "wt") as f:
            f.write(r[0])
        put(d + "/audit-2026-09-01T003000Z.jsonl", r[1] if rotated_prev_ok else self._chain(2)[1].replace("0000", "1111", 1))
        put(d + "/audit.jsonl", r[2])
        return d, make_cfg(d)

    def test_gz_rotated_vault_files_chain_is_anchored_on_the_gz(self):
        d, cfg = self._gz_setup()
        st = State(d)
        self.assertEqual([f["rule"] for f in checks.check_vault(cfg, st, True, T0)], [])
        self.assertIn("audit-2026-08-01T003000Z.jsonl.gz", st.get("vault_gz"))
        self.assertTrue(st.get("vault_gz")["audit-2026-08-01T003000Z.jsonl.gz"]["last"])

    def test_first_plain_record_not_continuing_from_gz_is_high(self):
        d, cfg = self._gz_setup()
        import gzip
        other = self._chain(1)[0].replace("\"i\": 0", "\"i\": 7")
        with gzip.open(d + "/audit-2026-08-01T003000Z.jsonl.gz", "wt") as f:
            f.write(json.dumps({"event": "other", "prev_hash": "0" * 64, "hash": "ab" * 32}) + "\n")
        out = checks.check_vault(cfg, State(d), True, T0)
        self.assertEqual([f["rule"] for f in out], ["vault-chain-broken"])

    def test_vanished_gz_within_retention_is_high_and_after_is_not(self):
        d, cfg = self._gz_setup()
        st = State(d)
        gz = d + "/audit-2026-08-01T003000Z.jsonl.gz"
        checks.check_vault(cfg, st, True, T0)
        mt = os.stat(gz).st_mtime
        os.remove(gz)
        out = checks.check_vault(cfg, st, False, mt + 86400)
        self.assertIn("vault-audit-missing", [f["rule"] for f in out])
        st2 = State(d)
        st2.set("vault_gz", {"audit-2026-08-01T003000Z.jsonl.gz": {"key": "k", "mtime": mt, "last": "x"}})
        out = checks.check_vault(cfg, st2, False, mt + 400 * 86400)
        self.assertNotIn("vault-audit-missing", [f["rule"] for f in out])

    def test_rotation_tail_of_the_old_inode_is_still_read(self):
        d = tempfile.mkdtemp()
        live = d + "/audit.jsonl"
        r = self._chain(3)
        put(live, r[0])
        st = State(d)
        recs, ok = sources.read_vault_new(live, st)
        self.assertEqual(len(recs), 1)
        with open(live, "a") as f:
            f.write(r[1])                                          # written after our last read, then rotated
        os.rename(live, d + "/audit-2026-09-01T003000Z.jsonl")
        put(live, r[2])
        recs, ok = sources.read_vault_new(live, st)
        self.assertEqual([x["i"] for x in recs], [1, 2])


class ManifestTable(unittest.TestCase):
    def test_tree_targets_match_apply_sh_table(self):
        apply = open(os.path.join(ROOT, "..", "patches", "apply.sh")).read()
        want = {}
        for m in re.finditer(r'^\s+"[0-9a-z]+\|[^|]+\|([^|]+)\|([^|"]+)(?:\|[^"]*)?"$', apply, re.M):
            want.setdefault(m.group(1), set()).add(m.group(2))
        src = rd("bin", "itsec-make-manifest")
        ns = {}
        exec(src.split("def main")[0].split('import tempfile')[1], ns)
        got = {rel: set(markers) for rel, markers in ns["TREE_TARGETS"]}
        self.assertEqual(got, want)
        self.assertIn("services/agents.js", "".join(got))
        self.assertIn("// LOCAL-PATCH 0005b", got["node_modules/@paperclipai/server/dist/services/heartbeat.js"])

    def test_0013_markers_in_table(self):
        ns = {}
        exec(rd("bin", "itsec-make-manifest").split("def main")[0].split('import tempfile')[1], ns)
        t = dict(ns["TREE_TARGETS"])
        self.assertEqual(t["node_modules/@paperclipai/server/dist/services/authorization.js"], ["// LOCAL-PATCH 0013"])   # 0013a
        self.assertIn("// LOCAL-PATCH 0013", t["node_modules/@paperclipai/server/dist/routes/agents.js"])                # 0013b

    def test_tree_mode_records_all_six_markers(self):
        import subprocess
        d = tempfile.mkdtemp()
        ns = {}
        exec(rd("bin", "itsec-make-manifest").split("def main")[0].split('import tempfile')[1], ns)
        for rel, markers in [(r, [m.replace("// LOCAL-PATCH ", "") for m in ms if m not in ns["OPTIONAL_MARKERS"]]) for r, ms in ns["TREE_TARGETS"]]:
            if not markers:
                continue
            os.makedirs(os.path.dirname(os.path.join(d, rel)), exist_ok=True)
            put(os.path.join(d, rel), "".join(f"// LOCAL-PATCH {m}\n" for m in markers))
        out = d + "/m.json"
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "bin", "itsec-make-manifest"), "--tree", d, "--out", out],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        m = json.load(open(out))
        self.assertEqual(len(m), len(ns["TREE_TARGETS"]) - 1)     # the optional-only file is not recorded
        os.remove(os.path.join(d, "node_modules/@paperclipai/server/dist/services/agents.js"))
        put(os.path.join(d, "node_modules/@paperclipai/server/dist/services/agents.js"), "unpatched\n")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "bin", "itsec-make-manifest"), "--tree", d, "--out", out + "2"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
