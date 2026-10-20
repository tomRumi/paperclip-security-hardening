"""The file watch walks and hashes a tree the watched account controls, so both are bounded and nothing in it is skipped silently:
symlinked and unlistable directories are entries, a tree past the cap is a finding (and never "removed" files), a hash cache
spares unchanged files, a per-run byte budget and a per-file cap keep a run of sparse multi-GiB files far from the collector's
timeout. Every test runs under an alarm."""
import _bootstrap  # noqa: F401
import contextlib
import glob
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import signal
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from helpers import FakeRun, make_cfg, put, T0
from itsec import acl, checks, collect as C, sources
from itsec.core import State, load_config, read_findings

UID = os.getuid()
BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "itsec-collect")


def rules(fs):
    return [f["rule"] for f in fs]


def titles(fs, rule):
    return [f["title"] for f in fs if f["rule"] == rule]


class Bounds(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp(prefix="itsec-bounds-test-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.w = os.path.join(self.d, "w")
        os.makedirs(self.w)
        signal.signal(signal.SIGALRM, lambda *a: self.fail("the watch took far too long"))
        signal.alarm(60)
        self.addCleanup(signal.alarm, 0)
        self.st = State(self.d)

    def cfg(self, **over):
        return make_cfg(self.d, watch=[{"globs": [self.w], "severity": "HIGH"}], **over)

    def check(self, baseline=False, cfg=None):
        return checks.check_files(cfg or self.cfg(), self.st, baseline, T0)

    def fill(self, n, sub="", size=1):
        base = os.path.join(self.w, sub)
        os.makedirs(base, exist_ok=True)
        for i in range(n):
            put(os.path.join(base, f"f{i:05d}"), "x" * size)


class WalkTree(Bounds):
    def test_one_cap_counts_files_directories_and_links_together(self):
        for i in range(3):
            self.fill(2, f"d{i}")
        os.symlink("/etc", os.path.join(self.w, "l1"))
        os.symlink("/etc/passwd", os.path.join(self.w, "l2"))             # 3 directories + 6 files + 2 links = 11 entries
        paths, cut = sources.walk_tree(self.w, 11)
        self.assertFalse(cut)
        self.assertEqual(len(paths), 8)                                    # directories are walked, not recorded
        paths, cut = sources.walk_tree(self.w, 10)
        self.assertTrue(cut)
        self.assertLessEqual(len(paths), 8)
        self.assertEqual(sources.walk_tree(self.w, 10), (paths, True))     # the same cut every time

    def test_entries_come_in_name_order_depth_first(self):
        for name in ("b", "a", "c"):
            put(os.path.join(self.w, name), "x")
        os.makedirs(os.path.join(self.w, "bd"))
        put(os.path.join(self.w, "bd", "z"), "x")
        put(os.path.join(self.w, "bd", "a"), "x")
        paths, _ = sources.walk_tree(self.w)
        self.assertEqual([os.path.relpath(p, self.w) for p in paths], ["a", "b", "c", "bd/a", "bd/z"])

    def test_a_huge_directory_is_cut_while_it_is_listed(self):
        self.fill(60)
        paths, cut = sources.walk_tree(self.w, 10)
        self.assertTrue(cut)
        self.assertEqual(len(paths), 10)


class Directories(Bounds):
    def test_a_symlink_to_a_directory_is_an_entry_and_is_never_followed(self):
        outside = os.path.join(self.d, "outside")
        os.makedirs(outside)
        put(os.path.join(outside, "secret"), "s")
        os.symlink(outside, os.path.join(self.w, "link"))
        put(os.path.join(self.w, "plain"), "p")
        got = sources.expand_watch(self.cfg())
        self.assertEqual(sorted(os.path.relpath(p, self.w) for p in got), ["link", "plain"])
        self.check(baseline=True)
        put(os.path.join(outside, "new"), "n")                              # below the link: not the watch's business
        self.assertEqual(self.check(), [])
        other = os.path.join(self.d, "other")                               # but the link itself is
        os.makedirs(other)
        os.remove(os.path.join(self.w, "link"))
        os.symlink(other, os.path.join(self.w, "link"))
        fs = self.check()
        self.assertEqual([(f["rule"], f["severity"]) for f in fs], [("file-change", "HIGH")])
        self.assertIn("link", fs[0]["title"])
        self.assertTrue(fs[0]["evidence"][2].startswith("after=link:" + other))

    def test_an_unlistable_directory_is_an_entry_with_its_stat_signature(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses permissions")
        sub = os.path.join(self.w, "private")
        os.makedirs(sub)
        put(os.path.join(sub, "f"), "x")
        os.chmod(sub, 0)
        self.addCleanup(os.chmod, sub, 0o700)
        self.assertIn(sub, sources.expand_watch(self.cfg()))
        self.assertTrue(sources.file_signature(sub, UID, self.d).startswith("stat:"))   # not refused as "not a regular file"
        self.assertEqual(self.check(baseline=True), [])
        self.assertEqual(self.check(), [])
        os.utime(sub, (1, 1))                                               # something happened to it
        fs = self.check()
        self.assertEqual([(f["rule"], f["severity"]) for f in fs], [("file-change", "HIGH")])
        self.assertIn(sub, fs[0]["title"])

    def test_listable_again_shows_the_files_inside_as_created(self):
        if os.geteuid() == 0:
            self.skipTest("root bypasses permissions")
        sub = os.path.join(self.w, "private")
        os.makedirs(sub)
        put(os.path.join(sub, "evil.sh"), "x")
        os.chmod(sub, 0)
        self.addCleanup(os.chmod, sub, 0o700)
        self.check(baseline=True)
        os.chmod(sub, 0o700)
        fs = self.check()
        self.assertIn(("file-change", "HIGH"), [(f["rule"], f["severity"]) for f in fs])
        self.assertTrue(any("created" in t and "evil.sh" in t for t in titles(fs, "file-change")))


class Truncation(Bounds):
    def test_a_5000_file_tree_is_cut_at_3000_with_one_high_finding(self):
        self.fill(2500, "a")
        self.fill(2500, "b")
        self.assertEqual(len(sources.expand_watch(self.cfg())), 3000 - 2)    # 5000 files + 2 dirs seen, 3000 entries looked at
        fs = self.check(baseline=True)
        self.assertEqual([(f["rule"], f["severity"]) for f in fs], [("watch-truncated", "HIGH")])
        self.assertEqual(len(self.st.get("files")), 2998)
        fs = self.check()
        self.assertEqual([(f["rule"], f["severity"]) for f in fs], [("watch-truncated", "HIGH")])
        self.assertIn(self.w, fs[0]["title"])
        os.remove(os.path.join(self.w, "a", "f00000"))                       # a recorded file is gone: reported, the cut or not
        fs = self.check()                                                    # (the window moves on: one more file of b comes into view)
        self.assertEqual(rules(fs), ["watch-truncated", "file-change", "file-change"])
        self.assertEqual(sorted(t.split(":")[0] for t in titles(fs, "file-change")), ["Watched file created", "Watched file removed"])
        put(os.path.join(self.w, "a", "f00001"), "changed")                  # but a change there is still reported
        self.assertEqual(sorted(rules(self.check())), ["file-change", "watch-truncated"])

    def test_what_was_recorded_past_the_cut_is_still_checked(self):
        cfg = self.cfg(watch_max_objects=10)
        self.fill(6, "d1")
        self.fill(6, "d2")                                                   # entries: 2 directories + 12 files; the cut falls inside d2
        self.check(baseline=True, cfg=cfg)
        self.assertEqual(len(self.st.get("files")), 8)
        put(os.path.join(self.w, "a-early"), "x")                            # sorts first and pushes d2/f00001 out of view
        put(os.path.join(self.w, "d2", "f00001"), "tampered")                # recorded, so it is looked at by its own path all the same
        fs = self.check(cfg=cfg)
        self.assertEqual(sorted(rules(fs)), ["file-change", "file-change", "watch-truncated"])
        self.assertEqual(sorted(t.split(": ")[0] + os.path.basename(t) for t in titles(fs, "file-change")),
                         ["Watched file changedf00001", "Watched file createda-early"])
        self.assertIn(os.path.join(self.w, "d2", "f00001"), self.st.get("files"), "kept, not forgotten")
        fs = self.check(cfg=self.cfg())                                      # the cap is lifted: only what was out of view is new
        self.assertEqual(sorted(t.split(":")[0] for t in titles(fs, "file-change")), ["Watched file created"] * 4)
        self.assertEqual(rules(self.check(cfg=self.cfg())), [])
        os.remove(os.path.join(self.w, "d1", "f00003"))                      # removal is reported with or without the cap
        self.assertIn("removed", titles(self.check(cfg=self.cfg()), "file-change")[0])

    def test_a_glob_with_more_hits_than_the_cap_is_cut_too(self):
        for i in range(8):
            put(os.path.join(self.w, f"x{i}"), "x")
        cfg = make_cfg(self.d, watch=[{"globs": [self.w + "/x*"], "severity": "HIGH"}], watch_max_objects=5)
        trunc = []
        self.assertEqual(len(sources.expand_watch(cfg, truncated=trunc)), 5)
        self.assertEqual(trunc, [self.w])

    def test_rebaseline_does_not_carry_old_entries(self):
        cfg = self.cfg(watch_max_objects=5)
        self.fill(8)
        self.check(baseline=True, cfg=cfg)
        self.st.set("files", dict(self.st.get("files"), **{os.path.join(self.w, "gone"): "sha256:x"}))
        self.check(baseline=True, cfg=cfg)
        self.assertNotIn(os.path.join(self.w, "gone"), self.st.get("files"))


class Recorded(Bounds):
    """The cap only limits the discovery of NEW entries: a path already in the state is looked at by its own path every run."""
    CAP = 60

    def cap_cfg(self, *globs, **over):
        return make_cfg(self.d, watch=[{"globs": list(globs), "severity": "HIGH"}], watch_max_objects=self.CAP, **over)

    def junk(self, base, n=CAP + 100):
        os.makedirs(base, exist_ok=True)
        for i in range(n):
            put(os.path.join(base, f"a-junk{i:05d}"), "j")

    def changes(self, fs, kinds=("changed", "removed")):
        """[(kind, path)] of the file-change findings of these kinds (not 'created')."""
        out = []
        for f in fs:
            if f["rule"] == "file-change":
                kind, path = f["title"].replace("Watched file ", "").split(": ", 1)
                if kind in kinds:
                    out.append((kind, path))
        return sorted(out)

    def test_a_removed_file_is_reported_although_junk_before_it_cut_its_tree(self):
        user = os.path.join(self.w, "user")
        svc = os.path.join(user, "paperclipai.service")
        os.makedirs(user)
        put(svc, "[Service]\n")
        cfg = self.cap_cfg(user, svc)                                       # listed explicitly, and inside the walked directory
        self.check(baseline=True, cfg=cfg)
        self.junk(user)                                                     # sorts before paperclipai.service: the walk is cut before it
        self.assertEqual(rules(self.check(cfg=cfg)).count("watch-truncated"), 1)
        os.remove(svc)
        fs = self.check(cfg=cfg)
        self.assertIn(("removed", svc), self.changes(fs))
        self.assertIn("watch-truncated", rules(fs))

    def test_an_explicit_file_is_recorded_even_when_the_tree_around_it_was_cut_from_the_start(self):
        user = os.path.join(self.w, "user")
        svc = os.path.join(user, "paperclipai.service")
        self.junk(user)
        put(svc, "[Service]\n")
        cfg = self.cap_cfg(user, svc)
        self.check(baseline=True, cfg=cfg)
        self.assertIn(svc, self.st.get("files"))
        put(svc, "[Service]\nExecStart=/tmp/evil\n")
        self.assertIn(("changed", svc), self.changes(self.check(cfg=cfg)))
        os.remove(svc)
        self.assertIn(("removed", svc), self.changes(self.check(cfg=cfg)))

    def test_a_deletion_in_a_fully_walked_tree_inside_a_cut_tree_is_reported(self):
        user = os.path.join(self.w, "user")
        dropin = os.path.join(user, "paperclipai.service.d")
        os.makedirs(dropin)
        put(os.path.join(dropin, "override.conf"), "[Service]\nSandbox=yes\n")
        cfg = make_cfg(self.d, watch=[{"globs": [user], "severity": "HIGH"}, {"globs": [dropin], "severity": "HIGH"}],
                       watch_max_objects=self.CAP)
        self.junk(user)                                                     # the outer tree is cut ...
        self.check(baseline=True, cfg=cfg)
        os.remove(os.path.join(dropin, "override.conf"))                    # ... the drop-in directory has its own, complete watch
        fs = self.check(cfg=cfg)
        self.assertEqual(self.changes(fs), [("removed", os.path.join(dropin, "override.conf"))])
        self.assertEqual([f["severity"] for f in fs if f["rule"] == "file-change"], ["HIGH"])

    def test_decoy_agents_do_not_hide_a_modified_or_deleted_agent_settings_file(self):
        agents = os.path.join(self.d, "companies", "c1", "agents")
        real = [os.path.join(agents, f"z-agent{i}", ".claude", "settings.json") for i in range(3)]
        for f in real:
            os.makedirs(os.path.dirname(f))
            put(f, "{}")
        cfg = self.cap_cfg(os.path.join(self.d, "companies", "*", "agents", "*", ".claude", "settings*.json"))
        self.check(baseline=True, cfg=cfg)
        for i in range(self.CAP + 140):                                     # far more matching decoys than the cap
            os.makedirs(os.path.join(agents, f"a-decoy{i:04d}", ".claude"))
            put(os.path.join(agents, f"a-decoy{i:04d}", ".claude", "settings.json"), "{}")
        put(real[0], '{"hooks": "evil"}')
        os.remove(real[1])
        fs = self.check(cfg=cfg)
        self.assertIn("watch-truncated", rules(fs))
        self.assertEqual(self.changes(fs), [("changed", real[0]), ("removed", real[1])])
        self.assertEqual([f["severity"] for f in fs if f["rule"] == "file-change" and "created" not in f["title"]], ["HIGH", "HIGH"])
        self.assertEqual(self.changes(self.check(cfg=cfg)), [], "the next run has nothing new to say about them")

    def test_an_unchanged_recorded_path_past_the_cut_is_quiet_and_stays_recorded(self):
        user = os.path.join(self.w, "user")
        os.makedirs(user)
        put(os.path.join(user, "z-late"), "1")
        cfg = self.cap_cfg(user)
        self.check(baseline=True, cfg=cfg)
        self.junk(user)
        self.check(cfg=cfg)
        self.assertEqual(rules(self.check(cfg=cfg)), ["watch-truncated"])
        self.assertIn(os.path.join(user, "z-late"), self.st.get("files"))

    def test_the_state_of_a_cut_tree_does_not_grow_past_the_cap(self):
        user = os.path.join(self.w, "user")
        cfg = self.cap_cfg(user)
        self.junk(user, self.CAP + 10)
        self.check(baseline=True, cfg=cfg)
        for round_ in range(4):                                             # each round adds junk sorting before everything seen so far
            os.makedirs(user, exist_ok=True)
            for i in range(self.CAP):
                put(os.path.join(user, f"0-round{round_}-{i:04d}"), "j")
            self.check(cfg=cfg)
            self.assertLessEqual(len(self.st.get("files")), self.CAP)


class ParentSwap(Bounds):
    """A file is opened by its resolved path, so a directory above it swapped for a link to an identical copy must still show:
    the signature carries where the path resolves to."""
    CAP = 60

    def swap_for_link(self, parent):
        """parent becomes a symlink to an identical copy of itself."""
        copy = parent + "-copy"
        shutil.copytree(parent, copy, symlinks=True)
        os.rename(parent, parent + "-orig")
        os.symlink(copy, parent)
        return copy

    def changed(self, fs):
        return sorted(f["title"].split(": ", 1)[1] for f in fs if f["rule"] == "file-change" and f["title"].startswith("Watched file changed"))

    def test_an_explicit_file_whose_parent_directory_was_swapped_for_a_link_is_a_high_change(self):
        parent = os.path.join(self.w, ".claude")
        f = os.path.join(parent, "settings.json")
        os.makedirs(parent)
        put(f, '{"hooks": {}}')
        cfg = self.cfg()
        cfg["watch"] = [{"globs": [f], "severity": "HIGH"}]
        self.check(baseline=True, cfg=cfg)
        self.assertEqual(self.check(cfg=cfg), [])
        self.swap_for_link(parent)
        fs = self.check(cfg=cfg)
        self.assertEqual([(x["rule"], x["severity"]) for x in fs], [("file-change", "HIGH")])
        self.assertEqual(self.changed(fs), [f])
        self.assertEqual(self.check(cfg=cfg), [], "the next run has nothing new to say")

    def test_a_recorded_file_of_a_cut_tree_whose_parent_was_swapped_is_a_high_change(self):
        user = os.path.join(self.w, "user")
        f = os.path.join(user, "z-dir", "settings.json")
        os.makedirs(os.path.dirname(f))
        put(f, "{}")
        cfg = make_cfg(self.d, watch=[{"globs": [user], "severity": "HIGH"}], watch_max_objects=self.CAP)
        self.check(baseline=True, cfg=cfg)
        for i in range(self.CAP + 20):                                      # the tree is cut before z-dir from now on
            put(os.path.join(user, f"a-junk{i:04d}"), "j")
        self.assertIn("watch-truncated", rules(self.check(cfg=cfg)))
        self.assertIn(f, self.st.get("files"))
        self.swap_for_link(os.path.dirname(f))
        fs = self.check(cfg=cfg)
        self.assertEqual(self.changed(fs), [f])
        self.assertEqual([x["severity"] for x in fs if x["rule"] == "file-change" and f in x["title"]], ["HIGH"])

    def test_a_path_behind_a_legitimate_link_is_stable(self):
        real = os.path.join(self.d, "releases", "1.2.3")
        os.makedirs(real)
        put(os.path.join(real, "cli.js"), "x")
        os.symlink(real, os.path.join(self.d, "current"))
        f = os.path.join(self.d, "current", "cli.js")
        cfg = self.cfg()
        cfg["watch"] = [{"globs": [f, os.path.join(self.d, "current")], "severity": "HIGH"}]
        self.check(baseline=True, cfg=cfg)
        sig = self.st.get("files")[f]
        self.assertTrue(sig.startswith("sha256:") and sig.endswith("@" + os.path.join(real, "cli.js")), sig)
        for _ in range(3):
            self.assertEqual(self.check(cfg=cfg), [])
        os.remove(os.path.join(self.d, "current"))                          # the link now leads to an identical copy: a change
        shutil.copytree(real, real + "-b")
        os.symlink(real + "-b", os.path.join(self.d, "current"))
        self.assertIn(f, self.changed(self.check(cfg=cfg)))

    def test_a_path_without_a_link_has_no_resolved_part_and_a_final_link_is_still_a_link(self):
        f = os.path.join(self.w, "plain")
        put(f, "x")
        self.assertNotIn("@", sources.file_signature(f, UID, self.d))
        os.symlink(f, os.path.join(self.w, "ln"))
        sig = sources.file_signature(os.path.join(self.w, "ln"), UID, self.d)
        self.assertEqual(sig.split(":")[0], "link")
        self.assertNotIn("@", sig)


class SharedBudget(Bounds):
    """A wildcard pattern has ONE budget (watch_max_objects) for all its hits and their walks; what is recorded for it stays within it."""
    CAP = 20

    def cfg_for(self, *globs, **over):
        return make_cfg(self.d, watch=[{"globs": list(globs), "severity": "HIGH"}], watch_max_objects=self.CAP, **over)

    def test_many_directories_with_many_files_each_are_cut_as_one_pattern(self):
        n = self.CAP - 1                                                    # scaled 199 x 199 with a cap of 200: every part is under the cap
        for i in range(n):
            self.fill(n, f"d{i:03d}")
        cfg = self.cfg_for(self.w + "/*")
        trunc = []
        got = sources.expand_watch(cfg, truncated=trunc)
        self.assertEqual(trunc, [self.w])
        self.assertLessEqual(len(got), self.CAP)
        fs = self.check(baseline=True, cfg=cfg)
        self.assertEqual([(f["rule"], f["severity"]) for f in fs], [("watch-truncated", "HIGH")])
        self.assertLessEqual(len(self.st.get("files")), self.CAP)

    def test_the_shipped_glob_shape_with_directories_named_like_the_files_is_bounded(self):
        n = self.CAP - 1                                                    # companies/*/agents/*/.claude/settings*.json, every hit a directory
        for i in range(n):
            self.fill(n, os.path.join("companies", "c1", "agents", f"a{i:03d}", ".claude", "settings.json"))
        cfg = self.cfg_for(os.path.join(self.w, "companies", "*", "agents", "*", ".claude", "settings*.json"))
        fs = self.check(baseline=True, cfg=cfg)
        self.assertEqual([(f["rule"], f["severity"]) for f in fs], [("watch-truncated", "HIGH")])
        self.assertLessEqual(len(self.st.get("files")), self.CAP)
        self.assertEqual(rules(self.check(cfg=cfg)), ["watch-truncated"])
        self.assertLessEqual(len(self.st.get("files")), self.CAP)

    def test_one_patterns_hits_and_walks_just_within_the_budget_are_not_cut(self):
        self.fill(4, "d0")
        self.fill(4, "d1")                                                  # 2 hits + 8 files = 10 objects
        cfg = self.cfg_for(self.w + "/*")
        cfg["watch_max_objects"] = 10
        trunc = []
        self.assertEqual(len(sources.expand_watch(cfg, truncated=trunc)), 8)
        self.assertEqual(trunc, [])
        cfg["watch_max_objects"] = 9
        self.assertLessEqual(len(sources.expand_watch(cfg, truncated=trunc)), 9)
        self.assertEqual(trunc, [self.w])

    def test_each_pattern_has_its_own_budget_and_the_state_stays_within_the_sum(self):
        a, b = os.path.join(self.d, "A"), os.path.join(self.d, "B")
        cfg = self.cfg_for(a + "/*", b + "/*")
        for rnd in range(4):                                                # every round adds names sorting before all earlier ones
            for base in (a, b):
                for i in range(self.CAP * 2):
                    os.makedirs(os.path.join(base, f"0-r{rnd}-{i:03d}"), exist_ok=True)
                    put(os.path.join(base, f"0-r{rnd}-{i:03d}", "f"), "x")
            fs = self.check(baseline=(rnd == 0), cfg=cfg)
            self.assertLessEqual(len(self.st.get("files")), 2 * self.CAP)
            if rnd:
                self.assertEqual(sorted(f["rule"] for f in fs if f["rule"] == "watch-truncated"), ["watch-truncated"] * 2)

    def test_a_recorded_file_of_a_cut_pattern_is_still_checked(self):
        agents = os.path.join(self.d, "agents")
        f = os.path.join(agents, "z-agent", "settings.json")
        os.makedirs(os.path.dirname(f))
        put(f, "{}")
        cfg = self.cfg_for(agents + "/*/settings*.json")
        self.check(baseline=True, cfg=cfg)
        for i in range(self.CAP * 3):
            os.makedirs(os.path.join(agents, f"a-decoy{i:03d}"))
            put(os.path.join(agents, f"a-decoy{i:03d}", "settings.json"), "{}")
        self.check(cfg=cfg)
        put(f, '{"evil": 1}')
        fs = self.check(cfg=cfg)
        self.assertIn(("file-change", "HIGH"), [(x["rule"], x["severity"]) for x in fs if f in x["title"]])
        self.assertLessEqual(len(self.st.get("files")), self.CAP)


class GlobBounds(Bounds):
    """A glob reads a bounded number of directory entries, whether or not anything matches."""
    CAP = 10

    def counted(self):
        read = []
        real = os.scandir

        class Counting:
            def __init__(self, it):
                self.it = it

            def __enter__(self):
                self.it.__enter__()
                return self

            def __exit__(self, *a):
                return self.it.__exit__(*a)

            def __iter__(self):
                return self

            def __next__(self):
                e = next(self.it)
                read.append(e.name)
                return e

            def close(self):
                self.it.close()
        patcher = mock.patch.object(os, "scandir", lambda *a, **k: Counting(real(*a, **k)))
        patcher.start()
        self.addCleanup(patcher.stop)
        return read

    def test_a_wildcard_over_a_huge_directory_without_a_match_is_cut(self):
        many = os.path.join(self.d, "companies", "c1", "agents")
        os.makedirs(many)
        for i in range(400):
            os.makedirs(os.path.join(many, f"x{i:04d}"))                    # no .claude/settings.json anywhere
        cfg = make_cfg(self.d, watch=[{"globs": [os.path.join(self.d, "companies", "*", "agents", "*", ".claude", "settings*.json")],
                                       "severity": "HIGH"}], watch_max_objects=self.CAP)
        read = self.counted()
        trunc, problems = [], []
        self.assertEqual(sources.expand_watch(cfg, problems, trunc), {})
        self.assertLessEqual(len(read), self.CAP * 10 + 2)
        self.assertEqual(trunc, [os.path.join(self.d, "companies")])
        fs = checks.check_files(cfg, self.st, False, T0)
        self.assertEqual([(f["rule"], f["severity"]) for f in fs], [("watch-truncated", "HIGH")])

    def test_a_small_glob_is_unchanged(self):
        for name in ("settings.json", "settings.local.json", "other.json", ".hidden", "settings.txt"):
            put(os.path.join(self.w, name), "x")
        cfg = make_cfg(self.d, watch=[{"globs": [self.w + "/settings*.json", self.w + "/*.json", self.w + "/*"], "severity": "HIGH"}])
        trunc = []
        got = sources.expand_watch(cfg, truncated=trunc)
        self.assertEqual(sorted(os.path.relpath(p, self.w) for p in got),
                         ["other.json", "settings.json", "settings.local.json", "settings.txt"], "a wildcard does not match a leading dot")
        self.assertEqual(trunc, [])
        self.assertEqual(sorted(sources.bounded_glob(self.w + "/set*.json")[0]), sorted(glob.glob(self.w + "/set*.json")))
        self.assertEqual(sources.bounded_glob(self.w + "/nope/*.json"), ([], False))
        self.assertEqual(sources.bounded_glob(self.w + "/settings.json"), ([self.w + "/settings.json"], False))


def bin_module():
    loader = importlib.machinery.SourceFileLoader("itsec_collect_bin", BIN)
    spec = importlib.util.spec_from_loader("itsec_collect_bin", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class RecordingNotifier:
    name = "rec"

    def __init__(self):
        self.sent, self.beats = [], []

    def send(self, alert):
        self.sent.append(alert)
        return True, "ok"

    def heartbeat(self, summary):
        self.beats.append(summary)
        return True, "ok"


class Heartbeat(Bounds):
    def test_the_collector_always_sends_its_heartbeat_when_a_tree_is_cut(self):
        self.fill(2500, "a")
        self.fill(2500, "b")
        cfgfile = os.path.join(self.d, "config.json")
        put(cfgfile, json.dumps(self.cfg()))
        mod, notifier = bin_module(), RecordingNotifier()
        real = C.collect
        run = FakeRun({"ss": (0, ""), "ps": (0, "")})
        with mock.patch.object(mod, "build_notifier", lambda cfg: notifier), \
                mock.patch.object(C, "collect", lambda cfg, state, n: real(cfg, state, n, run, None, self.d + "/passwd", self.d + "/group")), \
                mock.patch.object(sys, "argv", ["itsec-collect", "--config", cfgfile]), contextlib.redirect_stdout(io.StringIO()):
            put(self.d + "/passwd", "root:x:0:0::/root:/bin/bash\n")
            put(self.d + "/group", "root:x:0:\n")
            self.assertEqual(mod.main(), 0)
            self.assertEqual(mod.main(), 0)
        self.assertEqual(len(notifier.beats), 2)
        self.assertEqual(len(notifier.sent), 1, "alerted once, then deduplicated")
        self.assertIn("more than 3000 entries", notifier.sent[0]["title"])
        stored = [f for f in read_findings(self.d, "2000") if f["rule"] == "watch-truncated"]
        self.assertEqual(len(stored), 2)
        self.assertTrue(all(f["severity"] == "HIGH" for f in stored))


class HashCache(Bounds):
    def setUp(self):
        super().setUp()
        self.f = os.path.join(self.w, "authorized_keys")
        put(self.f, "ssh-ed25519 AAAA owner\n")
        self.reads = []
        real = sources.sha256_file

        def counting(path, *a, **kw):
            self.reads.append(path)
            return real(path, *a, **kw)
        patcher = mock.patch.object(sources, "sha256_file", counting)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_unchanged_file_is_not_read_again_and_the_cache_survives_the_state_file(self):
        with mock.patch.object(sources, "_RACY_NS", 0):
            self.check(baseline=True)
            self.assertEqual(len(self.reads), 1)
            self.st.save()
            self.st = State(self.d)
            self.assertEqual(self.check(), [])
            self.assertEqual(len(self.reads), 1, "served from the cache")
            time.sleep(0.05)
            st = os.stat(self.f)
            put(self.f, "ssh-ed25519 BBBB attack\n"[:len("ssh-ed25519 AAAA owner\n") - 1] + "\n")   # same size ...
            os.utime(self.f, ns=(st.st_atime_ns, st.st_mtime_ns))                                      # ... same mtime ...
            fs = self.check()                                                                          # ... but ctime moved
            self.assertEqual(len(self.reads), 2)
            self.assertEqual([(f["rule"], f["severity"]) for f in fs], [("file-change", "HIGH")])

    def test_a_file_changed_a_moment_ago_is_not_cached(self):
        self.check(baseline=True)
        self.assertEqual(list(self.st.get("hash_cache")), [self.f])
        self.assertTrue(self.st.get("hash_cache")[self.f].endswith(":racy"))   # the key is on record, never reused as a hash
        self.check()
        self.assertEqual(len(self.reads), 2)                                # same-tick writes could hide behind equal timestamps

    def test_a_cache_entry_of_another_file_or_a_damaged_state_is_ignored(self):
        with mock.patch.object(sources, "_RACY_NS", 0):
            self.check(baseline=True)
            entry = self.st.get("hash_cache")[self.f]
            self.st.set("hash_cache", {self.f: entry.rsplit(":", 1)[0] + ":nothex"})
            self.check()
            self.assertEqual(len(self.reads), 2)
            self.st.set("hash_cache", ["not", "a", "dict"])
            self.check()
            self.assertEqual(len(self.reads), 3)


    def test_the_cache_key_includes_the_device(self):
        with mock.patch.object(sources, "_RACY_NS", 0):
            self.check(baseline=True)
            self.assertEqual(self.check(), [])
            self.assertEqual(len(self.reads), 1)
            st = os.stat(self.f)
            elsewhere = SimpleNamespace(st_dev=st.st_dev + 1, st_ino=st.st_ino, st_size=st.st_size, st_mtime_ns=st.st_mtime_ns,
                                        st_ctime_ns=st.st_ctime_ns)                    # same inode number, size and times on another device
            hasher = sources.Hasher(self.st.get("hash_cache"))
            self.assertIsNone(hasher.lookup(self.f, elsewhere))
            self.assertIsNotNone(sources.Hasher(self.st.get("hash_cache")).lookup(self.f, st))


class Budget(Bounds):
    def setUp(self):
        super().setUp()
        self.sizes = []
        real = sources.sha256_file

        def counting(path, *a, **kw):
            self.sizes.append((path, os.path.getsize(path)))
            return real(path, *a, **kw)
        patcher = mock.patch.object(sources, "sha256_file", counting)
        patcher.start()
        self.addCleanup(patcher.stop)

    def sparse(self, n, size, sub=""):
        base = os.path.join(self.w, sub)
        os.makedirs(base, exist_ok=True)
        for i in range(n):
            with open(os.path.join(base, f"s{i:03d}"), "wb") as f:
                f.truncate(size)

    def test_150_sparse_gib_files_are_neither_read_nor_slow(self):
        self.sparse(150, 1 << 30)                                           # 150 GiB "of data": the old run hashed all of it
        t0 = time.monotonic()
        fs = self.check(baseline=True)
        took = time.monotonic() - t0
        self.assertLess(took, 20)
        self.assertEqual(self.sizes, [], "over the per-file cap: not read at all")
        self.assertEqual(len([f for f in fs if f["rule"] == "watch-unsafe"]), 150)
        self.assertTrue(all(f["severity"] == "HIGH" and "oversize" in f["title"] for f in fs if f["rule"] == "watch-unsafe"))
        self.assertTrue(all(s.startswith("refused:oversize:") and len(s.split(":")) == 9 for s in self.st.get("files").values()))
        sig = self.st.get("files")[os.path.join(self.w, "s000")]
        with open(os.path.join(self.w, "s000"), "r+b") as f:                 # growing it by one byte changes the signature
            f.truncate((1 << 30) + 1)
        self.assertNotEqual(sources.file_signature(os.path.join(self.w, "s000"), UID, self.d), sig)

    def test_files_within_the_cap_stop_at_the_per_run_budget(self):
        mib = 1 << 20
        self.sparse(40, 4 * mib)                                            # scaled: 40 x 4 MiB, cap 8 MiB, budget 16 MiB
        cfg = self.cfg(hash_file_cap_bytes=8 * mib, hash_budget_bytes=16 * mib)
        t0 = time.monotonic()
        fs = self.check(baseline=True, cfg=cfg)
        self.assertLess(time.monotonic() - t0, 20)
        self.assertEqual(sum(s for _, s in self.sizes), 16 * mib)
        self.assertEqual(len(self.sizes), 4)
        budget = [f for f in fs if f["rule"] == "hash-budget-exceeded"]
        self.assertEqual([(f["severity"], f["count"]) for f in budget], [("MEDIUM", 36)])
        self.assertEqual(rules(fs).count("hash-budget-exceeded"), 1)
        self.assertEqual(len([s for s in self.st.get("files").values() if s.startswith("stat:")]), 36)
        # the next run: what was hashed is served from the cache, a further slice is hashed, still one finding
        self.sizes.clear()
        with mock.patch.object(sources, "_RACY_NS", 0):
            self.check(baseline=True, cfg=cfg)
            self.sizes.clear()
            fs = self.check(cfg=cfg)
        self.assertLessEqual(sum(s for _, s in self.sizes), 16 * mib)
        self.assertEqual(rules(fs).count("hash-budget-exceeded"), 1)

    def test_a_changed_file_past_the_budget_is_still_a_finding(self):
        put(os.path.join(self.w, "a"), "1")
        put(os.path.join(self.w, "b"), "1")
        cfg = self.cfg(hash_budget_bytes=0)
        with mock.patch.object(sources, "_RACY_NS", 0):
            self.check(baseline=True, cfg=self.cfg())
            time.sleep(0.05)
            put(os.path.join(self.w, "b"), "2")
            fs = self.check(cfg=cfg)
        self.assertEqual(sorted(rules(fs)), ["file-change", "hash-budget-exceeded"])   # compared by stat signature: the change shows
        self.assertEqual([f["severity"] for f in fs if f["rule"] == "file-change"], ["HIGH"])

    def test_a_file_the_budget_does_not_reach_is_not_reported_changed_when_nothing_proves_it(self):
        f = os.path.join(self.w, "a")
        put(f, "1")
        self.check(baseline=True)                                           # hashed a moment after it was written: not cached
        sig = self.st.get("files")[f]
        self.assertTrue(sig.startswith("sha256:"))
        fs = self.check(cfg=self.cfg(hash_budget_bytes=0))
        self.assertEqual([(x["rule"], x["severity"]) for x in fs], [("hash-budget-exceeded", "MEDIUM")])
        self.assertEqual(fs[0]["evidence"], [f])
        self.assertEqual(self.st.get("files")[f], sig, "the old signature is kept, not replaced by a stat signature")
        self.assertEqual(self.check(), [])

    def test_a_file_modified_since_its_last_hash_is_a_change_even_when_that_hash_was_too_fresh_to_cache(self):
        f = os.path.join(self.w, "a")
        put(f, "1")
        self.check(baseline=True)                                           # hashed a moment after it was written: only its stat key is kept
        put(f, "2")
        fs = self.check(cfg=self.cfg(hash_budget_bytes=0))
        self.assertEqual(sorted((x["rule"], x["severity"]) for x in fs), [("file-change", "HIGH"), ("hash-budget-exceeded", "MEDIUM")])
        self.assertEqual(rules(self.check(cfg=self.cfg(hash_budget_bytes=0))), ["hash-budget-exceeded"])   # reported once, then stat against stat
        self.assertEqual(self.check(), [])                                  # hashed again: the same file as the stat signature already reported

    def test_a_skipped_file_with_no_record_of_its_last_hash_is_a_change(self):
        f = os.path.join(self.w, "a")
        put(f, "1")
        self.check(baseline=True)
        self.st.set("hash_cache", {})
        fs = self.check(cfg=self.cfg(hash_budget_bytes=0))
        self.assertEqual(sorted((x["rule"], x["severity"]) for x in fs), [("file-change", "HIGH"), ("hash-budget-exceeded", "MEDIUM")])

    def test_a_skipped_files_record_survives_runs_without_budget(self):
        f = os.path.join(self.w, "a")
        put(f, "1")
        self.check(baseline=True)
        for _ in range(3):
            self.assertEqual(rules(self.check(cfg=self.cfg(hash_budget_bytes=0))), ["hash-budget-exceeded"])
        self.assertTrue(self.st.get("hash_cache")[f].endswith(":racy"))
        self.assertEqual(self.check(), [])

    def attack_cfg(self, **over):
        return make_cfg(self.d, watch=[{"globs": [os.path.join(self.w, "decoys")], "severity": "HIGH"},
                                       {"globs": [os.path.join(self.w, "t", "*")], "severity": "HIGH"}], **over)

    def test_decoys_in_an_earlier_entry_cannot_keep_a_modified_file_undecided(self):
        mib = 1 << 20
        self.sparse(3, 4 * mib, "decoys")                                   # each run, the first decoy takes the whole budget
        target = os.path.join(self.w, "t", "hook.sh")
        os.makedirs(os.path.dirname(target))
        put(target, "echo ok\n")
        small = self.attack_cfg(hash_file_cap_bytes=8 * mib, hash_budget_bytes=4 * mib)
        self.check(baseline=True, cfg=self.attack_cfg(hash_file_cap_bytes=8 * mib))   # everything is hashed too fresh to cache: only the keys are kept
        put(target, "echo attack\n")
        fs = self.check(cfg=small)
        self.assertIn(target, [f["title"].rsplit(": ", 1)[1] for f in fs if f["rule"] == "file-change"])
        self.assertEqual([f["severity"] for f in fs if f["rule"] == "file-change" and f["title"].endswith(target)], ["HIGH"])

    def test_files_named_in_the_config_and_recorded_ones_are_hashed_before_new_discoveries(self):
        mib = 1 << 20
        named = os.path.join(self.w, "named")
        put(named, "n")
        self.sparse(3, 4 * mib, "decoys")
        cfg = make_cfg(self.d, watch=[{"globs": [os.path.join(self.w, "decoys")], "severity": "HIGH"}, {"globs": [named], "severity": "HIGH"}],
                       hash_file_cap_bytes=8 * mib, hash_budget_bytes=4 * mib)
        self.check(baseline=True, cfg=cfg)
        self.assertEqual(self.sizes[0][0], named, "hashed first, before the decoys use up the budget")

    def test_a_file_hashed_after_a_run_without_budget_is_not_reported_changed(self):
        for name in ("a", "b", "c"):
            put(os.path.join(self.w, name), name)
        with mock.patch.object(sources, "_RACY_NS", 0):
            fs = self.check(baseline=True, cfg=self.cfg(hash_budget_bytes=0))
            self.assertTrue(all(s.startswith("stat:") for s in self.st.get("files").values()))
            self.assertEqual(rules(self.check(cfg=self.cfg(hash_budget_bytes=0))), ["hash-budget-exceeded"])   # stat against stat
            fs = self.check()                                               # budget again: the files are hashed for the first time
            self.assertEqual(fs, [], "the same files, only compared differently now")
            self.assertTrue(all(s.startswith("sha256:") for s in self.st.get("files").values()))
            self.assertEqual(self.check(), [])

    def test_a_file_that_really_changed_while_it_was_compared_by_size_and_time_is_still_reported(self):
        for name in ("a", "b"):
            put(os.path.join(self.w, name), name)
        with mock.patch.object(sources, "_RACY_NS", 0):
            self.check(baseline=True, cfg=self.cfg(hash_budget_bytes=0))
            time.sleep(0.05)
            put(os.path.join(self.w, "b"), "B")
            fs = self.check()
        self.assertEqual([(f["rule"], f["severity"], f["title"].split(": ")[0]) for f in fs],
                         [("file-change", "HIGH", "Watched file changed")])
        self.assertTrue(fs[0]["title"].endswith("/b"))

    def test_a_file_over_the_per_file_cap_is_not_read(self):
        self.sparse(1, 3 << 20)
        cfg = self.cfg(hash_file_cap_bytes=1 << 20)
        fs = self.check(baseline=True, cfg=cfg)
        self.assertEqual(rules(fs), ["watch-unsafe"])
        self.assertEqual(self.sizes, [])


if __name__ == "__main__":
    unittest.main()
