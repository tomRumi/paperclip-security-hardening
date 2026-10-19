import _bootstrap  # noqa: F401
import os
import tempfile
import unittest

from helpers import make_cfg, put, open_read, T0
from itsec import lynis
from itsec.core import read_findings

R1 = "hardening_index=70\nwarning[]=SSH-7440|root login|\nsuggestion[]=AUTH-9286|min pass age|\nsuggestion[]=KRNL-5820|core dumps|\n"
R2 = "hardening_index=65\nwarning[]=SSH-7440|root login|\nwarning[]=NETW-3200|bad protocol|\nsuggestion[]=AUTH-9286|min pass age|\n"


class Lynis(unittest.TestCase):
    def runner(self, report):
        def run(cmd, timeout=60, env=None):
            self.cmd = cmd
            put(cmd[cmd.index("--report-file") + 1], report)
            return 0, ""
        return run

    def test_parse_and_diff(self):
        d = lynis.diff(lynis.parse_report(R1), lynis.parse_report(R2))
        self.assertEqual(d["new_warnings"], ["NETW-3200|bad protocol|"])
        self.assertEqual(d["gone_suggestions"], ["KRNL-5820|core dumps|"])
        self.assertEqual((d["index_before"], d["index_after"]), (70, 65))

    def test_two_runs_diff_reported(self):
        d = tempfile.mkdtemp()
        cfg = make_cfg(d)
        f1 = lynis.run_lynis(cfg, self.runner(R1), T0)
        self.assertEqual(f1[0]["rule"], "lynis-baseline")
        f2 = lynis.run_lynis(cfg, self.runner(R2), T0 + 7 * 86400)
        self.assertEqual((f2[0]["rule"], f2[0]["severity"]), ("lynis-diff", "MEDIUM"))
        self.assertTrue(any("new warning: NETW-3200" in e for e in f2[0]["evidence"]))
        self.assertIn("--pentest", self.cmd)                         # runs unprivileged
        self.assertEqual(len(read_findings(d, "2000-01-01T00:00:00Z")), 2)
        f3 = lynis.run_lynis(cfg, self.runner(R2), T0 + 14 * 86400)
        self.assertEqual(f3[0]["severity"], "INFO")                  # unchanged: no regression

    def test_lynis_missing(self):
        d = tempfile.mkdtemp()
        f = lynis.run_lynis(make_cfg(d), lambda *a, **k: (127, ""), T0)
        self.assertEqual((f[0]["rule"], f[0]["severity"]), ("lynis-failed", "MEDIUM"))


if __name__ == "__main__":
    unittest.main()
