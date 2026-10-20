"""itsec.acl: the read access of the watchdog account on another account's files, without following symlinks.
Real directories, real setfacl, no root: as a normal user an ACL entry for any numeric uid can be set on one's own files.
Skipped when setfacl is missing or the temp directory's file system has no ACL support.
  PCSH_TEST_SCRATCH  parent directory for the scratch files (default: the OS temp dir)"""
import _bootstrap  # noqa: F401
import contextlib
import io
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from itsec import acl

UID = os.getuid()
USER = "65000"          # an id with no account: setfacl takes numeric ids
OTHER = "65001"
BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "itsec-acl")


def getfacl(path):
    r = subprocess.run(["getfacl", "-c", "-p", "--", path], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def has(path, user=USER, perm=None):
    return any(l.startswith(f"user:{user}:") and (perm is None or l.split(":")[2].split("\t")[0] == perm) for l in getfacl(path).splitlines())


def plain(path):        # no extended ACL at all (no `+`)
    return not os.listxattr(path, follow_symlinks=False)


def probe():
    if not shutil.which("setfacl") or not shutil.which("getfacl"):
        return False
    d = tempfile.mkdtemp(dir=os.environ.get("PCSH_TEST_SCRATCH"))
    try:
        f = os.path.join(d, "f")
        open(f, "w").close()
        return subprocess.run(["setfacl", "-m", f"u:{USER}:r", f], capture_output=True).returncode == 0
    finally:
        shutil.rmtree(d, ignore_errors=True)


def fstat_failing(names=(), dev_offset_names=()):
    """An os.fstat that fails with EACCES for descriptors that name one of `names` (a FUSE mount root may not look into) and
    reports another st_dev for those of `dev_offset_names` (a mount point), as seen through /proc/self/fd."""
    real = os.fstat

    def fake(fd):
        try:
            leaf = os.path.basename(os.readlink(f"/proc/self/fd/{fd}"))
        except (OSError, TypeError):
            leaf = ""
        if leaf in names:
            raise PermissionError(13, "Permission denied")
        st = real(fd)
        if leaf in dev_offset_names:
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev + 1, st.st_nlink, st.st_uid, st.st_gid, st.st_size,
                                   int(st.st_atime), int(st.st_mtime), int(st.st_ctime)))
        return st
    return fake


class ReadChecked(unittest.TestCase):
    """acl.read_checked: root's one way to read a file of the watched account. Needs no ACL support."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="itsec-read-test-", dir=os.environ.get("PCSH_TEST_SCRATCH")))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        signal.signal(signal.SIGALRM, lambda *a: self.fail("read_checked blocked"))
        signal.alarm(20)                                    # a FIFO that is opened or read blocking would hang here
        self.addCleanup(signal.alarm, 0)

    def put(self, rel, data=b"x"):
        p = os.path.join(self.tmp, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def test_reads_a_regular_file_and_leaves_no_descriptor_open(self):
        f = self.put("a/b.js", b"// LOCAL-PATCH 0001\n")
        before = len(os.listdir("/proc/self/fd"))
        self.assertEqual(acl.read_checked(f), b"// LOCAL-PATCH 0001\n")
        self.assertEqual(acl.read_checked(f, UID), b"// LOCAL-PATCH 0001\n")
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_a_fifo_is_refused_without_blocking(self):
        fifo = os.path.join(self.tmp, "fifo")
        os.mkfifo(fifo)
        with self.assertRaises(acl.Refused) as cm:
            acl.read_checked(fifo, UID)
        self.assertIn("not a regular file", str(cm.exception))

    def test_a_device_and_a_symlink_to_one_are_refused(self):
        with self.assertRaises(acl.Refused) as cm:
            acl.read_checked("/dev/zero")
        self.assertIn("not a regular file", str(cm.exception))
        os.symlink("/dev/zero", os.path.join(self.tmp, "zero"))
        with self.assertRaises(acl.Refused) as cm:
            acl.read_checked(os.path.join(self.tmp, "zero"))
        self.assertIn("symlink", str(cm.exception))

    def test_a_directory_is_refused(self):
        os.makedirs(os.path.join(self.tmp, "d"))
        with self.assertRaises(acl.Refused):
            acl.read_checked(os.path.join(self.tmp, "d"))

    def test_a_file_over_the_cap_is_refused_and_not_read(self):
        self.assertEqual(acl.READ_CAP, 64 << 20)
        big = os.path.join(self.tmp, "big")
        with open(big, "wb") as f:
            f.truncate(acl.READ_CAP + 1)                    # sparse: costs nothing
        with self.assertRaises(acl.Refused) as cm:
            acl.read_checked(big)
        self.assertIn("limit", str(cm.exception))
        small = self.put("small", b"0123456789")
        self.assertEqual(acl.read_checked(small, cap=10), b"0123456789")
        with self.assertRaises(acl.Refused):
            acl.read_checked(small, cap=9)

    def test_a_file_that_grows_while_it_is_read_is_still_capped(self):
        f = self.put("grow", b"x" * 20)
        real = os.fstat
        with mock.patch.object(acl.os, "fstat", lambda fd: real(fd) if os.readlink(f"/proc/self/fd/{fd}") != f else
                               os.stat_result((stat.S_IFREG | 0o644, 1, 1, 1, UID, 0, 5, 0, 0, 0))):        # reports 5 bytes, holds 20
            with self.assertRaises(acl.Refused):
                acl.read_checked(f, cap=10)

    def test_symlinks_anywhere_in_the_path_are_refused(self):
        real = self.put("real/f", b"x")
        os.symlink(os.path.join(self.tmp, "real"), os.path.join(self.tmp, "dlink"))
        os.symlink(real, os.path.join(self.tmp, "flink"))
        for p in ("dlink/f", "flink"):
            with self.assertRaises(acl.Refused, msg=p):
                acl.read_checked(os.path.join(self.tmp, p))

    def test_a_missing_file_is_not_a_refusal(self):
        with self.assertRaises(FileNotFoundError):
            acl.read_checked(os.path.join(self.tmp, "nope"))
        with self.assertRaises(FileNotFoundError):
            acl.read_checked(os.path.join(self.tmp, "nope", "deeper"))

    def test_only_plain_absolute_paths(self):
        for p in ("rel/f", f"{self.tmp}/../x", f"{self.tmp}//x"):
            with self.assertRaises(acl.Refused, msg=p):
                acl.read_checked(p)

    @unittest.skipIf(os.geteuid() == 0, "root owns everything the check lets through")
    def test_the_owner_check_applies_when_a_uid_is_given(self):
        f = self.put("f")
        with self.assertRaises(acl.Refused) as cm:
            acl.read_checked(f, UID + 1)
        self.assertIn("neither the watched account nor root", str(cm.exception))
        self.assertEqual(acl.read_checked(f, UID), b"x")

    def test_a_stat_or_open_error_is_a_refusal_not_a_crash(self):
        f = self.put("m/f")
        with mock.patch.object(acl.os, "fstat", fstat_failing(names=("m",))):
            with self.assertRaises(acl.Refused) as cm:
                acl.read_checked(f)
        self.assertIn("cannot look at it", str(cm.exception))
        with mock.patch.object(acl, "_open_data", side_effect=PermissionError(13, "Permission denied")):
            with self.assertRaises(acl.Refused):
                acl.read_checked(f)


@unittest.skipUnless(probe(), "setfacl/getfacl and a file system with ACL support are needed")
class Acl(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="itsec-acl-test-", dir=os.environ.get("PCSH_TEST_SCRATCH")))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.home = self.mk("home")
        self.outside = self.mk("outside")        # the other account's files: must never be touched

    def mk(self, rel, text=None, mode=None):
        p = os.path.join(self.tmp, rel)
        if text is None:
            os.makedirs(p, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        if mode is not None:
            os.chmod(p, mode)
        return p

    def grant(self, kind, path, uid=UID):
        return acl.apply("grant", kind, path, uid, USER)

    def remove(self, kind, path, uid=UID):
        return acl.apply("remove", kind, path, uid, USER)

    # ---------------------------------------------------------------- grant
    def test_grants_traversal_on_a_directory_and_read_on_a_file(self):
        d = self.mk("home/.claude")
        f = self.mk("home/.claude/settings.json", "{}", 0o600)
        self.assertEqual(self.grant("x", d), 0)
        self.assertEqual(self.grant("r", f), 0)
        self.assertTrue(has(d, perm="--x"))
        self.assertTrue(has(f, perm="r--"))
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode) & 0o007, 0, "nothing for others")
        self.assertFalse(has(self.mk("home/.claude/other", "x"), perm=None))

    def test_a_tree_gets_read_everywhere_and_no_execute_bit_on_files(self):
        t = self.mk("home/skills")
        a = self.mk("home/skills/a.md", "a", 0o644)
        s = self.mk("home/skills/sub/deep/b.sh", "b", 0o755)
        self.assertEqual(self.grant("R", t), 0)
        self.assertTrue(has(t, perm="r-x") and has(os.path.dirname(s), perm="r-x"))
        self.assertTrue(has(a, perm="r--"))
        self.assertTrue(has(s, perm="r-x"), "an executable file stays executable for it, a plain one does not become so")

    def test_a_symlink_inside_a_tree_is_not_followed_and_not_touched(self):
        t = self.mk("home/skills")
        secret = self.mk("outside/secret", "s", 0o600)
        os.symlink(secret, os.path.join(t, "link"))
        os.symlink(self.outside, os.path.join(t, "dirlink"))
        self.mk("home/skills/ok", "ok")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.grant("R", t), 0)
        self.assertIn("left out 2", err.getvalue())
        self.assertTrue(has(os.path.join(t, "ok")))
        self.assertTrue(plain(secret) and plain(self.outside))

    def test_a_large_tree_is_handled_in_batches(self):
        t = self.mk("home/many")
        files = [self.mk(f"home/many/d{i % 4}/f{i}", "x") for i in range(25)]
        open_fds = len(os.listdir("/proc/self/fd"))
        old, acl.BATCH = acl.BATCH, 4
        self.addCleanup(setattr, acl, "BATCH", old)
        self.assertEqual(self.grant("R", t), 0)
        self.assertTrue(all(has(f) for f in files))
        self.assertEqual(self.remove("R", t), 0)
        self.assertTrue(all(plain(f) for f in files) and plain(t))
        self.assertEqual(len(os.listdir("/proc/self/fd")), open_fds, "no descriptor is left open")

    # ---------------------------------------------------------------- tree size cap
    def test_a_tree_past_the_object_cap_is_refused_before_anything_is_changed(self):
        t = self.mk("home/big")
        files = [self.mk(f"home/big/d{i % 3}/f{i}", "x") for i in range(20)]      # 3 directories + 20 files below the top
        open_fds = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(acl, "MAX_OBJECTS", 22):
            with self.assertRaises(acl.Refused) as cm:
                self.grant("R", t)
            self.assertEqual(cm.exception.kind, "oversize")
            self.assertTrue(plain(t) and all(plain(f) for f in files), "the counting pass touches nothing")
            with self.assertRaises(acl.Refused):
                self.remove("R", t)
        with mock.patch.object(acl, "MAX_OBJECTS", 23):                            # exactly at the cap: fine
            self.assertEqual(self.grant("R", t), 0)
            self.assertTrue(all(has(f) for f in files))
        self.assertEqual(len(os.listdir("/proc/self/fd")), open_fds, "no descriptor is left open")

    def test_one_huge_directory_is_not_read_to_the_end(self):
        t = self.mk("home/flat")
        for i in range(30):
            self.mk(f"home/flat/f{i}", "x")
        with mock.patch.object(acl, "MAX_OBJECTS", 10):
            with mock.patch.object(os, "scandir", wraps=os.scandir) as sd:
                with self.assertRaises(acl.Refused):
                    self.grant("R", t)
                self.assertEqual(sd.call_count, 1)

    def test_the_command_line_exits_2_for_a_tree_past_the_cap(self):
        t = self.mk("home/big")
        for i in range(5):
            self.mk(f"home/big/f{i}", "x")
        code = f"import sys; sys.path.insert(0, {os.path.dirname(os.path.dirname(os.path.abspath(acl.__file__)))!r}); from itsec import acl; acl.MAX_OBJECTS = 3; sys.exit(acl.main(sys.argv[1:]))"
        r = subprocess.run([sys.executable, "-I", "-c", code, "--uid", str(UID), "--user", USER, "grant", "R", t], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("refused", r.stderr)
        self.assertTrue(plain(t))

    # ---------------------------------------------------------------- objects root cannot look at, mounts
    def test_a_stat_error_inside_a_tree_leaves_that_object_out(self):
        t = self.mk("home/tree")
        ok = self.mk("home/tree/ok", "x")
        bad = self.mk("home/tree/bad/inner", "x")        # "bad": a FUSE mount root may not look into
        also = self.mk("home/tree/sub/ok2", "x")
        with mock.patch.object(acl.os, "fstat", fstat_failing(names=("bad",))), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.grant("R", t), 0)
        self.assertIn("left out 1", err.getvalue())
        self.assertTrue(has(ok) and has(also))
        self.assertTrue(plain(os.path.dirname(bad)) and plain(bad))

    def test_an_open_error_inside_a_tree_leaves_that_object_out(self):
        t = self.mk("home/tree")
        ok = self.mk("home/tree/ok", "x")
        bad = self.mk("home/tree/bad", "x")
        real = acl._open_path

        def opening(name, dir_fd, directory):
            if name == "bad":
                raise PermissionError(13, "Permission denied")
            return real(name, dir_fd, directory)
        with mock.patch.object(acl, "_open_path", opening), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.grant("R", t), 0)
        self.assertIn("left out 1", err.getvalue())
        self.assertTrue(has(ok) and plain(bad))

    def test_another_file_system_inside_a_tree_is_not_entered(self):
        t = self.mk("home/tree")
        ok = self.mk("home/tree/ok", "x")
        mnt = self.mk("home/tree/mnt", None)
        inner = self.mk("home/tree/mnt/inner", "x")
        other = self.mk("home/tree/sub/deeper/ok2", "x")
        with mock.patch.object(acl.os, "fstat", fstat_failing(dev_offset_names=("mnt",))), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.grant("R", t), 0)
        self.assertIn("left out 1", err.getvalue())
        self.assertTrue(has(ok) and has(other))
        self.assertTrue(plain(mnt) and plain(inner), "neither the mount point nor anything below it")
        with mock.patch.object(acl.os, "fstat", fstat_failing(dev_offset_names=("mnt",))), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.remove("R", t), 0)
        self.assertTrue(plain(ok) and plain(other))

    def test_a_stat_error_on_the_path_itself_is_a_refusal(self):
        d = self.mk("home/.claude")
        f = self.mk("home/.claude/settings.json", "{}", 0o600)
        for kind, p in (("r", f), ("x", d), ("R", d)):
            with mock.patch.object(acl.os, "fstat", fstat_failing(names=(".claude",))):
                with self.assertRaises(acl.Refused, msg=kind) as cm:
                    self.grant(kind, p)
            self.assertIn("cannot look at it", str(cm.exception))
        self.assertTrue(plain(d) and plain(f))

    def test_the_command_line_reports_a_stat_error_as_a_refusal(self):
        f = self.mk("home/.claude/settings.json", "{}", 0o600)
        with mock.patch.object(acl.os, "fstat", fstat_failing(names=(".claude",))), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(acl.main(["--uid", str(UID), "--user", USER, "grant", "r", f]), 2)
        self.assertIn("refused", err.getvalue())

    # ---------------------------------------------------------------- symlinks and races
    def test_a_symlink_in_the_middle_of_the_path_is_refused_and_nothing_outside_is_touched(self):
        target = self.mk("outside/settings.json", "{}", 0o600)
        os.symlink(self.outside, os.path.join(self.home, ".claude"))
        for kind, p in (("r", f"{self.home}/.claude/settings.json"), ("x", f"{self.home}/.claude"), ("R", f"{self.home}/.claude/sub")):
            with self.assertRaises(acl.Refused, msg=kind) as cm:
                self.grant(kind, p)
            self.assertIn("symlink", str(cm.exception))
        self.assertTrue(plain(target) and plain(self.outside))

    def test_a_symlink_as_the_last_component_is_refused(self):
        target = self.mk("outside/f", "x")
        os.symlink(target, os.path.join(self.home, "link"))
        os.symlink(self.outside, os.path.join(self.home, "dlink"))
        for kind, name in (("r", "link"), ("R", "dlink"), ("x", "dlink")):
            with self.assertRaises(acl.Refused):
                self.grant(kind, os.path.join(self.home, name))
        self.assertTrue(plain(target) and plain(self.outside))

    def test_a_swap_after_the_check_does_not_redirect_the_grant(self):
        """The watched account replaces .claude by a symlink while the helper is between two components: the helper already
        holds the real directory, so the grant lands on it and the symlink's target stays untouched."""
        real = self.mk("home/.claude/settings.json", "{}", 0o600)
        target = self.mk("outside/settings.json", "{}", 0o600)
        real_open = acl._open_path

        def swapping(name, dir_fd, directory):
            fd = real_open(name, dir_fd, directory)
            if name == ".claude":
                os.rename(f"{self.home}/.claude", f"{self.home}/.claude.moved")
                os.symlink(self.outside, f"{self.home}/.claude")
            return fd

        acl._open_path = swapping
        self.addCleanup(setattr, acl, "_open_path", real_open)
        self.assertEqual(self.grant("r", real), 0)
        self.assertTrue(plain(target), "the other directory was not touched")
        self.assertTrue(has(f"{self.home}/.claude.moved/settings.json"), "the original file got the entry")

    def test_a_plain_file_where_a_directory_belongs_is_refused(self):
        self.mk("home/file", "x")
        with self.assertRaises(acl.Refused):
            self.grant("r", f"{self.home}/file/inner")

    def test_only_plain_absolute_paths(self):
        for p in ("home/x", f"{self.home}/../outside", f"{self.home}//x", f"{self.home}/./x", "/"):
            with self.assertRaises(acl.Refused, msg=p):
                self.grant("r", p)

    def test_a_directory_is_not_a_file_and_the_other_way_round(self):
        f = self.mk("home/f", "x")
        for kind, p in (("r", self.home), ("x", f), ("R", f)):
            with self.assertRaises(acl.Refused):
                self.grant(kind, p)

    # ---------------------------------------------------------------- owner
    @unittest.skipIf(os.geteuid() == 0, "root owns everything the check lets through")
    def test_a_component_owned_by_somebody_else_is_refused(self):
        f = self.mk("home/f", "x")
        with self.assertRaises(acl.Refused) as cm:
            self.grant("r", f, uid=UID + 1)           # "the watched account" is another uid: these files are a stranger's
        self.assertIn("neither the watched account nor root", str(cm.exception))
        self.assertTrue(plain(f))
        self.grant("r", f, uid=UID)

    def test_foreign_owned_objects_in_a_tree_are_left_out(self):
        t = self.mk("home/tree")
        mine = self.mk("home/tree/mine", "x")
        theirs = self.mk("home/tree/theirs", "x")
        ino = os.stat(theirs).st_ino
        real = acl._owned
        acl._owned = lambda st, uid: st.st_ino != ino and real(st, uid)
        self.addCleanup(setattr, acl, "_owned", real)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.grant("R", t), 0)
        self.assertTrue(has(mine))
        self.assertTrue(plain(theirs))

    # ---------------------------------------------------------------- remove
    def test_remove_takes_the_entry_away_and_leaves_no_trace_when_nothing_else_is_there(self):
        f = self.mk("home/f", "x", 0o640)
        d = self.mk("home/d", None)
        os.chmod(d, 0o750)
        before = [stat.S_IMODE(os.stat(p).st_mode) for p in (f, d)]
        self.grant("r", f)
        self.grant("x", d)
        self.assertFalse(plain(f))
        self.assertEqual(self.remove("r", f), 0)
        self.assertEqual(self.remove("x", d), 0)
        self.assertFalse(has(f) or has(d))
        self.assertTrue(plain(f) and plain(d), "no leftover mask: no `+` in ls -l")
        self.assertEqual([stat.S_IMODE(os.stat(p).st_mode) for p in (f, d)], before, "the mode bits are as they were")

    def test_remove_keeps_other_entries_and_their_mask(self):
        f = self.mk("home/f", "x", 0o640)
        subprocess.run(["setfacl", "-m", f"u:{OTHER}:r", f], check=True)
        self.grant("r", f)
        self.assertEqual(self.remove("r", f), 0)
        self.assertTrue(has(f, OTHER, "r--") and not has(f))
        self.assertIn("mask::", getfacl(f))

    def test_remove_keeps_a_directorys_default_entries(self):
        d = self.mk("home/d", None)
        subprocess.run(["setfacl", "-d", "-m", f"u:{OTHER}:r", d], check=True)
        self.grant("x", d)
        self.assertEqual(self.remove("x", d), 0)
        self.assertIn(f"default:user:{OTHER}:r--", getfacl(d))
        self.assertFalse(has(d))

    def test_remove_on_a_tree(self):
        t = self.mk("home/tree")
        fs = [self.mk("home/tree/a", "a"), self.mk("home/tree/s/b", "b")]
        self.grant("R", t)
        self.assertTrue(all(has(f) for f in fs))
        self.assertEqual(self.remove("R", t), 0)
        self.assertTrue(all(plain(f) for f in fs + [t]))

    def test_remove_tolerates_a_path_that_was_never_granted_or_is_gone(self):
        f = self.mk("home/f", "x")
        d = self.mk("home/d", None)
        self.assertEqual(self.remove("r", f), 0)
        self.assertEqual(self.remove("x", d), 0)
        self.assertEqual(self.remove("R", d), 0)
        self.assertEqual(self.remove("r", f"{self.home}/never/existed"), 0)
        self.assertEqual(self.grant("r", f"{self.home}/never/existed"), 0)
        self.assertTrue(plain(f) and plain(d))

    def test_remove_refuses_a_swapped_in_symlink_too(self):
        target = self.mk("outside/settings.json", "{}")
        subprocess.run(["setfacl", "-m", f"u:{USER}:r", target], check=True)       # an entry that must survive
        os.symlink(self.outside, os.path.join(self.home, ".claude"))
        with self.assertRaises(acl.Refused):
            self.remove("r", f"{self.home}/.claude/settings.json")
        self.assertTrue(has(target))

    # ---------------------------------------------------------------- command line
    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", BIN, "--uid", str(UID), "--user", USER, *args], capture_output=True, text=True)

    def test_command_line_exit_codes(self):
        f = self.mk("home/f", "x")
        self.assertEqual(self.cli("grant", "r", f).returncode, 0)
        self.assertTrue(has(f))
        self.assertEqual(self.cli("remove", "r", f).returncode, 0)
        os.symlink(self.outside, os.path.join(self.home, "l"))
        r = self.cli("grant", "R", f"{self.home}/l/x")
        self.assertEqual(r.returncode, 2)
        self.assertIn("refused", r.stderr)
        r = self.cli("grant", "r", f, "--uid")                     # usage error
        self.assertEqual(r.returncode, 2)
        r = subprocess.run([sys.executable, "-I", BIN, "--uid", str(UID), "--user", "no-such-account-xyz", "grant", "r", f], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, "setfacl failing is reported")
        self.assertNotIn("/proc/self/fd", r.stderr)


if __name__ == "__main__":
    unittest.main()
