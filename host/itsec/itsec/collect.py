"""The collector: one deterministic pass. Rules detect; delivery sends HIGH findings once per dedup window."""
import hashlib
import time

from . import checks, logrules, sources
from .core import State, append_findings, make_finding, now_ts, SEV_RANK
from .notify import alert_for_finding


def _day(now):
    return time.strftime("%Y-%m-%d", time.gmtime(now))


def deliver(state, notifier, findings, cfg, now):
    """Send each HIGH finding once per dedup window. Failures stay in the persisted outbox and are retried.
    at most cfg alert_cap_per_run NEW issues are created per run; the overflow becomes ONE aggregate HIGH issue,
    so forged or runaway findings cannot flood the board. Sent issues are remembered (alert_log) for the  recheck."""
    notified = state.get("notified", {})
    window = cfg["dedup_hours"] * 3600
    notified = {k: t for k, t in notified.items() if now - t < window * 2}
    outbox = {f["dedup_key"]: f for f in state.get("outbox", [])}
    for f in findings:
        if f["severity"] == "HIGH" and now - notified.get(f["dedup_key"], -window) >= window:
            outbox.setdefault(f["dedup_key"], f)
    sent, failed = [], []
    cap = cfg.get("alert_cap_per_run", 10)
    alert_log = state.get("alert_log", {})
    pending = [(k, f) for k, f in outbox.items() if not (k in notified and now - notified[k] < window)]
    for k in [k for k in outbox if k not in dict(pending)]:
        del outbox[k]
    over = pending[cap:]
    pending = pending[:cap]
    if over:
        agg = {"ts": findings[0]["ts"] if findings else "", "rule": "alert-flood", "severity": "HIGH",
               "title": f"Alert flood: {len(over)} further HIGH findings were suppressed this run", "source": "collector",
               "evidence": [f"{f['rule']}: {f['title']}" for _, f in over[: cfg["evidence_max"]]], "count": len(over),
               "dedup_key": f"alert-flood:{_day(now)}"}
        findings.append(agg)
        for k, _ in over:
            notified[k] = now                       # summarised in the aggregate (the findings stay in the findings store)
            outbox.pop(k, None)
        pending.append((agg["dedup_key"], agg))
    for key, f in pending:
        alert = alert_for_finding(f)
        alert["day"] = _day(now)
        ok, info = notifier.send(alert)
        if ok:
            notified[key] = now
            outbox.pop(key, None)
            sent.append(key)
            li = getattr(notifier, "last_issue", None)
            if li and li.get("id"):
                alert_log[li["id"]] = {"ts": now, "key": key, "title": alert["title"], "alert": alert,
                                       "body_sha": hashlib.sha256(alert["body"].encode()).hexdigest(), "reraised": 0}
        else:
            failed.append((key, info))
            outbox[key] = f
    state.set("notified", notified)
    state.set("outbox", list(outbox.values())[-200:])
    keep = now - cfg["paperclip"].get("alert_recheck_days", 7) * 86400
    state.set("alert_log", {i: m for i, m in alert_log.items() if m["ts"] >= keep})
    return sent, failed


def list_outbox(state):
    """[(dedup_key, title)] of the undelivered HIGH findings."""
    return [(f["dedup_key"], f.get("title", "")) for f in state.get("outbox", [])]


def drop_outbox(state, keys):
    """Remove outbox entries whose dedup_key equals one of keys EXACTLY (no wildcards). Returns the removed keys;
    the caller saves the state (atomic replace)."""
    want = set(keys)
    box = state.get("outbox", [])
    removed = [f["dedup_key"] for f in box if f["dedup_key"] in want]
    state.set("outbox", [f for f in box if f["dedup_key"] not in want])
    return removed


def recheck_alerts(state, notifier, cfg, now):
    """alerts created in the last N days must still exist, be open and be unedited. Otherwise raise HIGH
    'alert-tampered' and re-send the original alert under a fresh key (at most 3 times per alert)."""
    log = state.get("alert_log", {})
    if not log:
        return []
    out = []
    unknown = []
    for iid, reason in notifier.verify_alerts({i: {"title": m["title"], "body_sha": m["body_sha"]} for i, m in log.items()}):
        meta = log.get(iid)
        if reason.startswith("integrity unknown"):
            unknown.append(f"issue={iid}: {reason}")
            continue
        if meta is None:
            out.append(make_finding("alert-tampered", "HIGH", "Alert integrity check could not run", "notifier", [reason],
                                    f"alert-tampered:*:{_day(now)}", now, cfg))
            continue
        out.append(make_finding("alert-tampered", "HIGH", f"A delivered ITSec alert issue was tampered with: {meta['title'][:120]}",
                                "notifier", [f"issue={iid}", reason], f"alert-tampered:{iid}:{_day(now)}", now, cfg))
        if meta["reraised"] < 3:
            again = dict(meta["alert"], key=f"{meta['key']}|reraise{meta['reraised'] + 1}", day=_day(now),
                         title="[RE-RAISED] " + meta["alert"]["title"])
            ok, _ = notifier.send(again)
            meta["reraised"] += 1
            if ok:
                li = getattr(notifier, "last_issue", None)
                if li and li.get("id"):
                    log[li["id"]] = {"ts": now, "key": again["key"], "title": again["title"], "alert": again,
                                     "body_sha": hashlib.sha256(again["body"].encode()).hexdigest(), "reraised": meta["reraised"]}
                    del log[iid]
    if unknown:                                      # once per day (dedup key has the day), MEDIUM, no re-raise
        out.append(make_finding("alert-integrity-unknown", "MEDIUM", "Alert integrity unknown (closer not readable)",
                                "notifier", unknown[:10], f"alert-integrity-unknown:{_day(now)}", now, cfg))
    state.set("alert_log", log)
    return out


def collect(cfg, state, notifier, run=sources.run_cmd, now=None, passwd="/etc/passwd", group="/etc/group", rules=None,
            stream=None):
    now = now if now is not None else now_ts()
    baseline = state.fresh or state.corrupt or not state.get("baselined", False)
    findings = []
    if state.corrupt:
        findings.append(make_finding("state-corrupt", "MEDIUM", "itsec state file was corrupt; re-baselined", "state", [state.path],
                                     f"state-corrupt:{time.strftime('%Y-%m-%d', time.gmtime(now))}", now, cfg))
    rules = rules if rules is not None else logrules.load_rules(watched_user=cfg["watched_user"], cfg=cfg)
    step_fail = []

    def guarded(name, fn):
        try:
            return fn()
        except Exception as e:                      # one broken check must not blind the others
            step_fail.append(name)
            return [make_finding("check-error", "MEDIUM", f"Check '{name}' crashed", name, [f"{type(e).__name__}: {e}"],
                                 f"check-error:{name}:{time.strftime('%Y-%m-%d', time.gmtime(now))}", now, cfg)]

    if stream is None:
        stream = sources.stream_cmd if run is sources.run_cmd else sources.stream_from_run(run)

    def logs():
        res = sources.read_journal(cfg, state, stream)
        events, status, out = res["events"], res["status"], []
        day = _day(now)
        if res["gap"]:
            out.append(make_finding("journal-gap", "MEDIUM", "Watch degraded: the journal entry at our cursor no longer exists (vacuumed?); "
                                    "events between the runs may be lost", "journal", [f"cursor={state.get('journal_cursor')}"],
                                    f"journal-gap:{day}", now, cfg))
        if res["cursor"] and status in ("ok", "truncated", "timeout"):
            state.set("journal_cursor", res["cursor"])
        streak = state.get("journal_backlog_streak", 0) + 1 if status == "truncated" else 0
        state.set("journal_backlog_streak", streak)
        if status == "truncated":
            sev = "HIGH" if streak >= cfg.get("journal_backlog_high_runs", 3) else "MEDIUM"
            out.append(make_finding("watch-degraded", sev, "Watch degraded: journal backlog (volume exceeds what one run can read; "
                                    "possible flooding)", "journal", [f"runs_in_a_row={streak}", f"events_read={len(events)}"],
                                    f"watch-degraded:journal-backlog:{sev}:{day}", now, cfg))
        elif status == "timeout":
            out.append(make_finding("watch-degraded", "HIGH", "Watch degraded: the journal read timed out (flooding or a hung journald)",
                                    "journal", [f"events_read={len(events)}"], f"watch-degraded:journal-timeout:{day}", now, cfg))
        elif status == "error":
            events, ok2 = sources.read_auth_log(cfg, state)
            if not ok2:
                return out + [make_finding("source-unreadable", "MEDIUM", "Neither the journal nor auth.log is readable", "journal",
                                           [], f"source-unreadable:journal:{day}", now, cfg)]
            out.append(make_finding("watch-degraded", "MEDIUM", "Watch degraded: journal unreadable, fell back to auth.log (sender "
                                    "identity is unverified there; journal-only rules are blind)", "journal", [cfg["auth_log_fallback"]],
                                    f"watch-degraded:journal-fallback:{day}", now, cfg))
        return out + logrules.run_log_rules(events, rules, cfg, state, baseline, now)

    findings += guarded("logs", logs)
    findings += guarded("files", lambda: checks.check_files(cfg, state, baseline, now))
    findings += guarded("accounts", lambda: checks.check_accounts(cfg, state, baseline, now, passwd, group))
    findings += guarded("ports", lambda: checks.check_ports(cfg, state, baseline, now, run))
    findings += guarded("processes", lambda: checks.check_processes(cfg, state, baseline, now, run))
    findings += guarded("patches", lambda: checks.check_patches(cfg, state, baseline, now))
    findings += guarded("paperclip-process", lambda: checks.check_paperclip_process(cfg, state, baseline, now, run))
    findings += guarded("disk", lambda: checks.check_disk(cfg, state, baseline, now))
    findings += guarded("vault", lambda: checks.check_vault(cfg, state, baseline, now))
    if baseline:
        findings.append(make_finding("baseline", "INFO", "First run: baseline learned (no alerts raised this run)", "collector",
                                     [f"ssh_ips={len(state.get('ssh_seen_ips', {}))} files={len(state.get('files', {}))} "
                                      f"ports={len(state.get('ports', []))}"], f"baseline:{int(now)}", now, cfg))
    state.set("baselined", True)
    findings.sort(key=lambda f: -SEV_RANK[f["severity"]])
    findings += guarded("alert-recheck", lambda: recheck_alerts(state, notifier, cfg, now))
    findings.sort(key=lambda f: -SEV_RANK[f["severity"]])
    sent, failed = deliver(state, notifier, findings, cfg, now)
    for key, info in failed:
        if info.startswith("preempted"):
            pf = make_finding("alert-preempted", "HIGH", "An alert could not be created: the idempotency key was pre-empted by another issue",
                              "notifier", [f"alert={key}", info], f"alert-preempted:{_day(now)}", now, cfg)
            findings.append(pf)
            state.set("outbox", state.get("outbox", []) + [pf])
    state.set("last_run", now)
    return findings, sent, failed
