"""Weekly Lynis audit wrapper: run, parse the .dat report, diff against the previous run, emit findings."""
import os
import shutil
import time

from . import sources
from .core import append_findings, make_finding, now_ts


def parse_report(text):
    """Lynis report.dat (key=value lines) -> {'index': int|None, 'warnings': set, 'suggestions': set}."""
    index, warns, sugg = None, set(), set()
    for line in text.splitlines():
        k, _, v = line.partition("=")
        if k == "hardening_index":
            try:
                index = int(v)
            except ValueError:
                pass
        elif k == "warning[]":
            warns.add(v.strip())
        elif k == "suggestion[]":
            sugg.add(v.strip())
    return {"index": index, "warnings": warns, "suggestions": sugg}


def diff(prev, cur):
    return {"new_warnings": sorted(cur["warnings"] - prev["warnings"]), "gone_warnings": sorted(prev["warnings"] - cur["warnings"]),
            "new_suggestions": sorted(cur["suggestions"] - prev["suggestions"]),
            "gone_suggestions": sorted(prev["suggestions"] - cur["suggestions"]),
            "index_before": prev["index"], "index_after": cur["index"]}


def findings_from(prev, cur, cfg, now):
    day = time.strftime("%Y-%m-%d", time.gmtime(now))
    if prev is None:
        return [make_finding("lynis-baseline", "INFO", "First Lynis run (no previous report to compare)", "lynis",
                             [f"hardening_index={cur['index']} warnings={len(cur['warnings'])} suggestions={len(cur['suggestions'])}"],
                             f"lynis-baseline:{day}", now, cfg)]
    d = diff(prev, cur)
    worse = d["new_warnings"] or (d["index_before"] is not None and d["index_after"] is not None and d["index_after"] < d["index_before"])
    ev = [f"hardening_index {d['index_before']} -> {d['index_after']}"]
    ev += [f"new warning: {w}" for w in d["new_warnings"]] + [f"gone warning: {w}" for w in d["gone_warnings"]]
    ev += [f"new suggestion: {s}" for s in d["new_suggestions"]] + [f"gone suggestion: {s}" for s in d["gone_suggestions"]]
    cfg2 = dict(cfg, evidence_max=40)
    return [make_finding("lynis-diff", "MEDIUM" if worse else "INFO", "Weekly Lynis audit diff vs previous run", "lynis", ev,
                         f"lynis-diff:{day}", now, cfg2, len(ev) - 1)]


def run_lynis(cfg, run=sources.run_cmd, now=None):
    """Run the audit and diff. Needs the lynis binary (apt). Without root Lynis runs in --pentest (non-privileged) mode."""
    now = now if now is not None else now_ts()
    d = os.path.join(cfg["state_dir"], "lynis")
    os.makedirs(d, exist_ok=True)
    out = os.path.join(d, "report-new.dat")
    cmd = [cfg.get("lynis_cmd", "lynis"), "audit", "system", "--pentest", "--quiet", "--no-colors",
           "--report-file", out, "--logfile", os.path.join(d, "lynis.log")]
    if cfg.get("lynis_consume_root_report"):          # the root unit (itsec-lynis-root.service) already wrote report-new.dat
        rc = 0
    else:
        rc, _ = run(cmd, 1800)
    if rc in (124, 127) or not os.path.exists(out):
        f = make_finding("lynis-failed", "MEDIUM", "Weekly Lynis audit could not run", "lynis", [f"rc={rc}"],
                         f"lynis-failed:{time.strftime('%Y-%m-%d', time.gmtime(now))}", now, cfg)
        append_findings(cfg["state_dir"], [f])
        return [f]
    with open(out) as f:
        cur = parse_report(f.read())
    last = os.path.join(d, "report-last.dat")
    prev = None
    if os.path.exists(last):
        with open(last) as f:
            prev = parse_report(f.read())
    fs = findings_from(prev, cur, cfg, now)
    shutil.move(out, last)
    append_findings(cfg["state_dir"], fs)
    return fs
