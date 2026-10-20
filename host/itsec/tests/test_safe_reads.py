"""The collector never opens a file of a less trusted account the plain way: a FIFO, /dev/zero, a huge file or a swapped
symlink must neither hang it nor be read, and each is a finding. Every test runs under an alarm: a blocking open or read
fails the test instead of stalling the run."""
import _bootstrap  # noqa: F401
import hashlib
import json
import os
import shutil
import signal
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import make_cfg, write_chain, put, T0
from itsec import acl, checks, sources
from itsec.core import State, sha256_file

UID = os.getuid()


def rules(fs):
    return {f["rule"]: f["severity"] for f in fs}


class NoHang(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="itsec-safe-test-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        signal.signal(signal.SIGALRM, lambda *a: self.fail("blocked on a FIFO or an endless file"))
        signal.alarm(20)
        self.addCleanup(signal.alarm, 0)

    def fifo(self, name):
        p = os.path.join(self.d, name)
        os.mkfifo(p)
        return p

    def huge(self, name, size):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.truncate(size)                            # sparse: nothing is written
        return p

    def swapped_dir(self, name="real"):
        """<d>/link -> <d>/real: a directory component that became a symlink."""
        os.makedirs(os.path.join(self.d, name))
        os.symlink(os.path.join(self.d, name), os.path.join(self.d, "link"))
        return os.path.join(self.d, "link")


class OpenFile(NoHang):
    def test_regular_file_is_read_and_closed(self):
        p = os.path.join(self.d, "f")
        put(p, "abc")
        before = len(os.listdir("/proc/self/fd"))
        with acl.open_file(p, UID) as f:
            self.assertEqual(f.read(), b"abc")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_unsafe_files_are_refused_with_a_kind(self):
        link = self.swapped_dir()
        put(os.path.join(self.d, "real", "x"), "x")
        os.symlink("/dev/zero", os.path.join(self.d, "zero"))
        cases = {"not-regular": self.fifo("fifo"), "oversize": self.huge("big", acl.STREAM_CAP + 1),
                 "symlink-in-path": link + "/x"}
        for kind, path in cases.items():
            with self.assertRaises(acl.Refused, msg=kind) as cm:
                acl.open_file(path, UID)
            self.assertEqual(cm.exception.kind, kind)
        with self.assertRaises(acl.Refused) as cm:
            acl.open_file(os.path.join(self.d, "zero"), UID)             # the last component is a symlink
        self.assertEqual(cm.exception.kind, "symlink-in-path")
        with self.assertRaises(acl.Refused) as cm:
            acl.open_file("/dev/zero", UID)                              # a device
        self.assertEqual(cm.exception.kind, "not-regular")
        with self.assertRaises(acl.Refused) as cm:
            acl.open_file(os.path.join(self.d, "fifo"), UID + 1)
        self.assertEqual(cm.exception.kind, "foreign-owner")

    def test_denied_is_a_permission_error_not_a_refusal(self):
        with mock.patch.object(acl, "_open_data", side_effect=PermissionError(13, "Permission denied")):
            p = os.path.join(self.d, "f")
            put(p, "x")
            with self.assertRaises(PermissionError):
                acl.open_file(p, UID)
            with self.assertRaises(acl.Refused) as cm:                   # read_checked (the installer's reader) refuses
                acl.read_checked(p, UID)
            self.assertTrue(cm.exception.denied)

    def test_tail_read_of_a_growing_log_has_no_size_limit(self):
        p = self.huge("log", acl.STREAM_CAP + 1)
        with acl.open_file(p, UID, cap=None) as f:
            f.seek(acl.STREAM_CAP)
            self.assertEqual(f.read(), b"\0")

    def test_sha256_file_owner(self):
        p = os.path.join(self.d, "f")
        put(p, "abc")
        self.assertEqual(sha256_file(p, owner=UID), hashlib.sha256(b"abc").hexdigest())
        with self.assertRaises(acl.Refused):
            sha256_file(self.fifo("fifo"), owner=UID)
        with mock.patch.object(acl, "STREAM_CAP", 2):                    # a file that grows past the cap while it is read
            with mock.patch.object(acl, "open_file", lambda path, uid, cap=None: open(path, "rb")):
                with self.assertRaises(acl.Refused):
                    sha256_file(p, chunk=1, owner=UID)


class WatchedFiles(NoHang):
    """check_files / file_signature: the watched account's files."""

    def setUp(self):
        super().setUp()
        self.f = os.path.join(self.d, "settings.json")
        put(self.f, "{}\n", "w")
        self.cfg = make_cfg(self.d, watch=[{"globs": [self.f, self.d + "/sub"], "severity": "HIGH"}])
        self.ids = sources.watched_ids(self.cfg)

    def sig(self, path):
        return sources.file_signature(path, *self.ids)

    def replace(self, make):
        os.remove(self.f)
        make()

    def check(self, st=None):
        return checks.check_files(self.cfg, st or State(self.d), False, T0)

    def test_regular_file_hashes_as_before(self):
        self.assertTrue(self.sig(self.f).startswith("sha256:"))
        self.assertEqual(self.sig(self.f).split(":")[1], hashlib.sha256(b"{}\n").hexdigest())

    def test_fifo_is_refused_and_high(self):
        st = State(self.d)
        checks.check_files(self.cfg, st, True, T0)
        self.replace(lambda: os.mkfifo(self.f))
        self.assertTrue(self.sig(self.f).startswith("refused:not-regular:"))
        fs = self.check(st)
        self.assertEqual(rules(fs), {"watch-unsafe": "HIGH", "file-change": "HIGH"})
        self.assertIn("not-regular", [f for f in fs if f["rule"] == "watch-unsafe"][0]["title"])

    def test_fifo_in_a_watched_directory(self):
        os.makedirs(self.d + "/sub")
        os.mkfifo(self.d + "/sub/x.service")
        self.assertEqual(rules(self.check())["watch-unsafe"], "HIGH")

    def test_final_symlink_is_reported_as_a_link_and_never_followed(self):
        self.replace(lambda: os.symlink("/dev/zero", self.f))
        self.assertTrue(self.sig(self.f).startswith("link:/dev/zero:"))

    def test_device_behind_a_resolved_path_is_refused(self):
        with mock.patch.object(sources.os.path, "realpath", return_value="/dev/zero"):
            self.assertTrue(self.sig(self.f).startswith("refused:not-regular:"))

    def test_symlink_swapped_into_the_path_after_it_was_resolved_is_refused(self):
        link = self.swapped_dir()
        put(os.path.join(self.d, "real", "x"), "x")
        with mock.patch.object(sources.os.path, "realpath", return_value=link + "/x"):
            self.assertTrue(self.sig(self.f).startswith("refused:symlink-in-path:"))

    def test_symlinks_in_the_configured_path_are_resolved_once(self):
        # the example config watches .../cli/current/...: that link is legitimate, only a later swap is refused
        link = self.swapped_dir()
        put(os.path.join(self.d, "real", "x"), "x")
        self.assertTrue(self.sig(link + "/x").startswith("sha256:"))

    def test_oversize_file_is_refused(self):
        self.replace(lambda: self.huge("settings.json", acl.STREAM_CAP + 1))
        self.assertTrue(self.sig(self.f).startswith("refused:oversize:"))
        self.assertEqual(rules(self.check())["watch-unsafe"], "HIGH")

    def test_foreign_owner_in_the_path_is_refused(self):
        uid, home = UID + 1, self.d                                       # the file lies in the watched home, owned by someone else
        self.assertTrue(sources.file_signature(self.f, uid, home).startswith("refused:foreign-owner:"))

    def test_unreadable_still_falls_back_to_the_stat_signature(self):
        os.chmod(self.f, 0)
        if os.access(self.f, os.R_OK):
            self.skipTest("running as root")
        self.assertTrue(self.sig(self.f).startswith("stat:"))
        self.assertNotIn("watch-unsafe", rules(self.check()))

    def test_files_outside_the_home_are_opened_safely_too(self):
        outside = (UID + 1, "/home/nobody-here")                          # the file is root's, not the watched account's
        self.assertTrue(sources.file_signature(self.f, *outside).startswith("sha256:"))
        with mock.patch.object(acl, "open_file", wraps=acl.open_file) as opened:
            sources.file_signature(self.f, *outside)
        opened.assert_called_once_with(os.path.realpath(self.f), None, acl.STREAM_CAP)   # no owner check, but the safe open
        self.replace(lambda: os.mkfifo(self.f))
        self.assertTrue(sources.file_signature(self.f, *outside).startswith("refused:not-regular:"))   # a FIFO there does not hang
        self.replace(lambda: os.mkfifo(self.f))
        self.assertTrue(sources.file_signature(self.f).startswith("refused:not-regular:"))             # no uid known at all

    def test_auth_log_fallback_is_opened_safely(self):
        cfg = make_cfg(self.d)
        st = State(self.d)
        put(cfg["auth_log_fallback"], "Oct 13 06:00:00 host sshd[1]: Failed password for root\npartial")
        events, ok = sources.read_auth_log(cfg, st)
        self.assertTrue(ok)
        self.assertEqual(len(events), 1)
        self.assertEqual(sources.read_auth_log(cfg, st), ([], True))        # the offset moved on; the half line stays unread
        os.remove(cfg["auth_log_fallback"])
        os.mkfifo(cfg["auth_log_fallback"])
        self.assertEqual(sources.read_auth_log(cfg, State(self.d)), ([], False))   # unreadable, not a hang
        os.remove(cfg["auth_log_fallback"])
        os.symlink("/dev/zero", cfg["auth_log_fallback"])
        self.assertEqual(sources.read_auth_log(cfg, State(self.d)), ([], False))


class PatchedFiles(NoHang):
    def setUp(self):
        super().setUp()
        self.f1, self.f2 = self.d + "/agents.js", self.d + "/heartbeat.js"
        put(self.f1, "a\n// LOCAL-PATCH 0002\nb\n")
        put(self.f2, "x\n// LOCAL-PATCH 0003\n")
        self.cfg = make_cfg(self.d)
        self.manifest = {p: {"sha256": hashlib.sha256(Path(p).read_bytes()).hexdigest(), "markers": [m]}
                         for p, m in ((self.f1, "// LOCAL-PATCH 0002"), (self.f2, "// LOCAL-PATCH 0003"))}
        self.write()

    def write(self):
        put(self.cfg["patch_manifest"], json.dumps(self.manifest))
        os.chmod(self.cfg["patch_manifest"], 0o644)

    def check(self):
        return checks.check_patches(self.cfg, State(self.d), False, T0)

    def test_intact_is_clean(self):
        self.assertEqual(self.check(), [])

    def test_the_cli_current_link_in_the_manifest_key_still_works(self):
        link = self.swapped_dir("inst")
        put(os.path.join(self.d, "inst", "a.js"), "z\n// LOCAL-PATCH 0001\n")
        self.manifest = {link + "/a.js": {"sha256": hashlib.sha256(b"z\n// LOCAL-PATCH 0001\n").hexdigest(), "markers": ["// LOCAL-PATCH 0001"]}}
        self.write()
        self.assertEqual(self.check(), [])

    def assert_unsafe(self, fs):
        self.assertEqual(rules(fs), {"patch-file-unsafe": "HIGH"})

    def test_fifo_is_high_and_does_not_hang(self):
        os.remove(self.f1)
        os.mkfifo(self.f1)
        fs = self.check()
        self.assert_unsafe(fs)
        self.assertIn("agents.js", " ".join(fs[0]["evidence"]))

    def test_device_is_high(self):
        os.remove(self.f1)
        os.symlink("/dev/zero", self.f1)                                  # resolved once to /dev/zero: not a regular file
        self.assert_unsafe(self.check())

    def test_symlink_swapped_in_after_resolution_is_high(self):
        link = self.swapped_dir()
        put(os.path.join(self.d, "real", "x"), "x")
        with mock.patch.object(checks.os.path, "realpath", side_effect=lambda p: link + "/x" if p == self.f1 else p):
            self.assert_unsafe(self.check())

    def test_oversize_is_high(self):
        os.remove(self.f1)
        self.huge("agents.js", acl.READ_CAP + 1)
        self.assert_unsafe(self.check())

    def test_foreign_owner_is_high(self):
        self.cfg["watched_uid"] = str(UID + 1)                            # the files belong to someone else now
        self.assert_unsafe(self.check())

    def test_missing_stays_medium_degraded(self):
        os.remove(self.f1)
        self.assertEqual(rules(self.check()), {"watch-degraded": "MEDIUM"})


class VaultLog(NoHang):
    def setUp(self):
        super().setUp()
        self.cfg = make_cfg(self.d)
        self.log = self.cfg["vault_audit_log"]
        self.rec = {"agent": "a1", "issue": "i1", "credential": "c", "reason": "r", "decision": "deny", "ceiling": "none",
                    "time": "2026-10-13T06:00:00Z"}

    def check(self, baseline=False):
        return checks.check_vault(self.cfg, State(self.d), baseline, T0)

    def test_intact_log_is_clean(self):
        write_chain(self.log, [self.rec])
        self.assertNotIn("vault-log-unsafe", rules(self.check()))

    def test_fifo_live_log(self):
        os.mkfifo(self.log)
        fs = self.check()
        self.assertEqual(rules(fs).get("vault-log-unsafe"), "MEDIUM")
        self.assertEqual(len([f for f in fs if f["rule"] == "vault-log-unsafe"]), 1)   # verify and tail read: one finding
        self.assertEqual(self.check(baseline=True)[0]["rule"], "vault-log-unsafe")

    def test_fifo_rotated_log(self):
        write_chain(self.log, [self.rec])
        os.mkfifo(self.d + "/audit-20261001.jsonl")
        self.assertEqual(rules(self.check()).get("vault-log-unsafe"), "MEDIUM")

    def test_symlinked_log(self):
        write_chain(self.d + "/other.jsonl", [self.rec])
        os.symlink(self.d + "/other.jsonl", self.log)
        self.assertEqual(rules(self.check()).get("vault-log-unsafe"), "MEDIUM")

    def test_log_behind_a_symlinked_directory(self):
        link = self.swapped_dir()
        write_chain(self.d + "/real/audit.jsonl", [self.rec])
        self.cfg["vault_audit_log"] = link + "/audit.jsonl"
        self.assertEqual(rules(self.check()).get("vault-log-unsafe"), "MEDIUM")

    def test_device_log(self):
        os.symlink("/dev/zero", self.log)
        self.assertEqual(rules(self.check()).get("vault-log-unsafe"), "MEDIUM")

    def test_oversize_log(self):
        self.huge("audit.jsonl", acl.STREAM_CAP + 1)
        self.assertEqual(rules(self.check()).get("vault-log-unsafe"), "MEDIUM")

    def test_foreign_owner_log(self):
        write_chain(self.log, [self.rec])
        self.cfg["vault_uid"] = str(UID + 1)
        self.assertEqual(rules(self.check()).get("vault-log-unsafe"), "MEDIUM")

    def test_compressed_file_fifo(self):
        write_chain(self.log, [self.rec])
        os.mkfifo(self.d + "/audit-20261001.jsonl.gz")
        fs = self.check()
        self.assertEqual(rules(fs).get("vault-log-unsafe"), "MEDIUM")
        self.assertNotIn("source-unreadable", rules(fs))                   # one cause, one finding

    def test_gzip_bomb_is_refused(self):
        import gzip
        write_chain(self.log, [self.rec])
        with gzip.open(self.d + "/audit-20261001.jsonl.gz", "wb") as g:
            g.write(b"\n" * 4096)
        with mock.patch.object(acl, "STREAM_CAP", 1024):
            with self.assertRaises(acl.Refused):
                checks._gz_last_hash(self.d + "/audit-20261001.jsonl.gz")

    def test_a_log_that_cannot_be_read_is_medium_not_a_broken_chain(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses permissions")
        write_chain(self.log, [self.rec])
        os.chmod(self.log, 0)
        fs = self.check()
        self.assertEqual(rules(fs).get("source-unreadable"), "MEDIUM")
        self.assertNotIn("vault-chain-broken", rules(fs))
        self.assertNotIn("vault-log-unsafe", rules(fs))                      # denied is not tampering either

    def test_a_log_rotated_away_mid_run_is_medium_not_a_broken_chain(self):
        write_chain(self.log, [self.rec])
        with mock.patch.object(sources, "vault_files", return_value=[self.d + "/audit-20261001.jsonl", self.log]):
            fs = self.check()
        self.assertEqual(rules(fs).get("source-unreadable"), "MEDIUM")
        self.assertNotIn("vault-chain-broken", rules(fs))

    def test_a_real_break_is_still_high_and_unreadable_files_raise(self):
        write_chain(self.log, [self.rec, self.rec], tamper=lambda lines: lines[1].update(prev_hash="f" * 64))
        fs = self.check()
        self.assertEqual(rules(fs).get("vault-chain-broken"), "HIGH")
        self.assertNotIn("source-unreadable", rules(fs))
        with self.assertRaises(FileNotFoundError):                         # no verdict at all for a file that is not there
            checks.verify_chain([self.d + "/absent.jsonl"])

    def test_tail_reader_alone(self):
        os.mkfifo(self.log)
        with self.assertRaises(acl.Refused):
            sources.read_vault_new(self.log, State(self.d))
        with self.assertRaises(acl.Refused):
            checks.verify_chain([self.log])


if __name__ == "__main__":
    unittest.main()
