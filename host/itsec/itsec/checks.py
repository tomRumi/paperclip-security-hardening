"""State-based checks: file integrity, users/groups, listeners, processes, patch status, vault audit.
Each returns a list of findings and updates `state`. `baseline` = first run: learn, do not alert."""
import glob
import gzip
import hashlib
import io
import json
import os
import re
import time
import zlib

from . import acl, sources
from .core import make_finding, clean

PRIV_GROUPS = {"sudo", "admin", "root", "wheel", "adm", "docker", "lxd", "systemd-journal", "shadow", "disk", "vault", "itsec"}


def _day(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def _hashed_after_stat(path, before, after):
    """`before` was a stat signature (the hash budget was used up) and `after` the hash of the file that still has exactly that
    signature (ctime cannot be set by the file's owner): the file did not change, only the way it is compared."""
    return before.startswith("stat:") and after.startswith("sha256:") and sources.stat_signature(path) == before


def check_files(cfg, state, baseline, now):
    """Compare the watched files with the last run. The expensive part is bounded: a watched tree is read up to
    cfg watch_max_objects entries (HIGH 'watch-truncated' when it has more), and at most cfg hash_budget_bytes are hashed per run
    (MEDIUM 'hash-budget-exceeded': the rest is compared by stat signature, an unchanged file reuses the hash cached in the
    state), so a tree of huge files cannot run the collector past its timeout. The cap only limits the DISCOVERY of new
    entries: every path already recorded in the state is looked at by its own path each run, outside the capped walk, so a
    change or removal of a recorded file is always reported (the state of a cut tree stays within the cap, see expand_watch).
    A file named in the config without a wildcard is never cut. The budget goes first to the files named without a wildcard and
    to those already recorded, then to newly discovered ones, so decoys in an earlier entry cannot starve them. A file the hash
    budget did not reach, whose old signature is a hash, is only in the MEDIUM budget finding (and keeps its old signature until a
    run can hash it) where it still has the stat key it was last hashed under; any other key, or no record of one, is a change
    (HIGH): a file touched all the time (never cached) must not stay unverified behind decoys."""
    problems, truncated = [], []
    uid, home = sources.watched_ids(cfg)
    hasher = sources.Hasher(state.get("hash_cache"), cfg.get("hash_budget_bytes", sources.HASH_BUDGET),
                            cfg.get("hash_file_cap_bytes", sources.HASH_FILE_CAP))
    old = state.get("files", {})
    found = sources.expand_watch(cfg, problems, truncated, recorded={} if baseline else old)
    named = sources.named_paths(cfg)
    sigs = {p: sources.file_signature(p, uid, home, hasher) for p in sorted(found, key=lambda p: p not in old and p not in named)}
    cur = {p: (sev, sigs[p]) for p, sev in found.items()}
    if not baseline:
        for p in old:                               # the recorded paths the walk did not bring: past the cut, or gone
            if p in cur:
                continue
            sev = next((w.get("severity", "HIGH") for w in sources.covering_entries(cfg, p)
                        if not sources.excluded(p, w.get("exclude", []))), None)
            sig = sources.file_signature(p, uid, home, hasher) if sev else "missing"
            if sig != "missing":
                cur[p] = (sev, sig)
        for p in hasher.skipped:                    # an old hash against a stat signature: undecided only while the stat key is the one it was hashed under
            if old.get(p, "").startswith("sha256:") and hasher.unchanged_since_hash(p):
                cur[p] = (cur[p][0], old[p])        # undecided, not "changed": it is in the budget finding, compared when the budget allows
    state.set("hash_cache", hasher.cache)
    out = []
    for top in sorted(set(truncated)):
        out.append(make_finding("watch-truncated", "HIGH", f"Watched tree has more than {cfg.get('watch_max_objects', sources.WATCH_MAX_OBJECTS)} "
                                f"entries; new entries past the cut are not discovered: {top}", "file hashes",
                                [f"path={top}", "paths already recorded are still checked one by one; new files past the cut are not seen"],
                                f"watch-truncated:{top}:{_day(now)}", now, cfg))
    if hasher.skipped:
        out.append(make_finding("hash-budget-exceeded", "MEDIUM", f"Watch degraded: hash budget used up, {len(hasher.skipped)} changed or new file(s) "
                                "compared by size and time only", "file hashes", hasher.skipped[:cfg["evidence_max"]],
                                f"hash-budget-exceeded:{_day(now)}", now, cfg, len(hasher.skipped)))
    for p, (sev, sig) in sorted(cur.items()):     # a watched file turned FIFO / device / oversize / behind a symlink is itself suspect
        if sig.startswith("refused:"):
            out.append(make_finding("watch-unsafe", sev, f"Watched file is not safe to read ({sig.split(':')[1]}): {p}", "file hashes",
                                    [f"path={p}", f"not read: {sig}"], f"watch-unsafe:{p}:{_day(now)}", now, cfg))
    for path, why in problems:                      # a watch that cannot see its target is a degraded watch, not silence
        out.append(make_finding("watch-unreadable", "MEDIUM", f"Watch degraded: cannot reach watched path {path}", "file hashes",
                                [f"path={path}", why], f"watch-unreadable:{path}:{_day(now)}", now, cfg))
    if not baseline:
        for p, (sev, sig) in cur.items():
            if p not in old:
                kind, prev = "created", "-"
            elif old[p] != sig and not _hashed_after_stat(p, old[p], sig):
                kind, prev = "changed", old[p]
            else:
                continue
            out.append(make_finding("file-change", sev, f"Watched file {kind}: {p}", "file hashes",
                                    [f"path={p} {kind}", f"before={prev}", f"after={sig}"],
                                    f"file:{p}:{hashlib.sha256(sig.encode()).hexdigest()[:12]}", now, cfg))
        for p in old:
            if p not in cur and not any(sources.excluded(p, w.get("exclude", [])) for w in sources.covering_entries(cfg, p)):
                out.append(make_finding("file-change", "HIGH", f"Watched file removed: {p}", "file hashes",   # now-excluded paths just drop out
                                        [f"path={p} removed", f"before={old[p]}"], f"file:{p}:removed", now, cfg))
    state.set("files", {p: sig for p, (_, sig) in cur.items()})
    return out


def check_accounts(cfg, state, baseline, now, passwd="/etc/passwd", group="/etc/group"):
    users, groups = sources.parse_passwd(passwd), sources.parse_group(group)
    out = []
    if users is None or groups is None:
        return [make_finding("source-unreadable", "MEDIUM", "Cannot read /etc/passwd or /etc/group", "accounts",
                             [passwd, group], f"source-unreadable:accounts:{_day(now)}", now, cfg)]
    ou, og = state.get("users"), state.get("groups")
    if not baseline and ou is not None and og is not None:
        for u, v in users.items():
            if u not in ou:
                out.append(make_finding("new-user", "HIGH", f"New user account: {u}", "/etc/passwd",
                                        [f"{u} uid={v[0]} gid={v[1]} shell={v[2]}"], f"new-user:{u}", now, cfg))
            elif ou[u] != v:
                out.append(make_finding("user-changed", "HIGH", f"User account changed: {u}", "/etc/passwd",
                                        [f"before uid/gid/shell={ou[u]}", f"after={v}"], f"user-changed:{u}:{v}", now, cfg))
        for g, v in groups.items():
            if g not in og:
                out.append(make_finding("new-group", "MEDIUM", f"New group: {g}", "/etc/group",
                                        [f"{g} gid={v[0]} members={v[1]}"], f"new-group:{g}", now, cfg))
            elif og[g][1] != v[1]:
                added = sorted(set(v[1]) - set(og[g][1]))
                sev = "HIGH" if g in PRIV_GROUPS else "MEDIUM"
                out.append(make_finding("group-membership", sev, f"Group membership changed: {g}", "/etc/group",
                                        [f"{g}: added={added} removed={sorted(set(og[g][1]) - set(v[1]))}"],
                                        f"group-membership:{g}:{','.join(v[1])}", now, cfg))
    state.set("users", users)
    state.set("groups", groups)
    return out


def check_ports(cfg, state, baseline, now, run=sources.run_cmd):
    rc, text = run(cfg["ss_cmd"], 30)
    if rc != 0 and not text:
        return [make_finding("source-unreadable", "MEDIUM", "ss failed", "ss", [f"rc={rc}"], f"source-unreadable:ss:{_day(now)}", now, cfg)]
    cur = sources.parse_ss(text, cfg["ignore_udp_ephemeral_from"])
    old = state.get("ports")
    out = []
    if not baseline and old is not None:
        for e in cur:
            if e not in old:
                sev = "MEDIUM" if sources.is_loopback(e) else "HIGH"
                out.append(make_finding("new-listener", sev, f"New listening socket: {e}", "ss -tlnup",
                                        [e], f"new-listener:{e}", now, cfg))
    state.set("ports", sorted(set(cur) | set(old or [])))
    return out


def check_processes(cfg, state, baseline, now, run=sources.run_cmd):
    rc, text = run(cfg["ps_cmd"], 30)
    if rc != 0 and not text:
        return [make_finding("source-unreadable", "MEDIUM", "ps failed", "ps", [f"rc={rc}"], f"source-unreadable:ps:{_day(now)}", now, cfg)]
    if baseline:
        return []
    allow = [re.compile(p) for p in cfg["expected_process_patterns"]]
    out = []
    for comm in sources.parse_ps(text, cfg["watched_user"]):
        if not any(a.search(comm) for a in allow):
            out.append(make_finding("unexpected-process", "MEDIUM", f"Process of {cfg['watched_user']} outside the expected set: {comm}",
                                    "ps", [comm], f"proc:{comm}:{_day(now)}", now, cfg))
    return out


def _degraded(cfg, now, what, evidence, key):
    return make_finding("watch-degraded", "MEDIUM", f"Watch degraded: {what}", "patch manifest", evidence,
                        f"watch-degraded:{key}:{_day(now)}", now, cfg)


def check_patches(cfg, state, baseline, now, run=None):
    """pure in-process check, nothing under /home is executed. Each patched file is compared (sha256 and the
    LOCAL-PATCH markers) against a root-owned manifest written at install time by bin/itsec-make-manifest:
    {"<abs path>": {"sha256": "...", "markers": ["// LOCAL-PATCH 0001", ...]}}.
    Missing/unreadable manifest or file = MEDIUM 'watch degraded' (never a false HIGH); mismatch or missing marker = HIGH.
    The patched files belong to the watched account: each is read through acl.read_checked (symlinks resolved once, then no
    symlink, owner = the watched account or root, a regular file of at most 64 MiB). A FIFO, device, oversize file, foreign
    owner or swapped component is not read and is HIGH 'patch-file-unsafe' (it never hangs the collector)."""
    mpath = cfg["patch_manifest"]
    try:
        st = os.stat(mpath)
        with open(mpath) as f:
            manifest = json.load(f)
        if not isinstance(manifest, dict):
            raise ValueError("not an object")
    except OSError as e:
        return [_degraded(cfg, now, "patch manifest missing or unreadable", [mpath, e.strerror or type(e).__name__], "manifest")]
    except ValueError:
        return [_degraded(cfg, now, "patch manifest is not valid JSON", [mpath], "manifest")]
    if st.st_uid != cfg.get("patch_manifest_owner_uid", 0) or st.st_mode & 0o022:
        return [make_finding("patch-manifest-untrusted", "HIGH", "Patch manifest is not root-owned or is writable by others",
                             "patch manifest", [f"{mpath} uid={st.st_uid} mode={st.st_mode & 0o7777:o}"],
                             f"patch-manifest-untrusted:{_day(now)}", now, cfg)]
    out, bad, unreadable, unsafe = [], [], [], []
    uid = sources.watched_ids(cfg)[0]
    for path, spec in sorted(manifest.items()):
        try:                                        # the manifest key may name the .../cli/current link: resolved once, here
            data = acl.read_checked(os.path.realpath(path), uid)
        except acl.Refused as e:
            if e.denied:
                unreadable.append(f"{path}: permission denied")
            else:
                unsafe.append(str(e))
            continue
        except OSError as e:
            unreadable.append(f"{path}: {e.strerror or type(e).__name__}")
            continue
        digest = hashlib.sha256(data).hexdigest()
        missing = [m for m in spec.get("markers", []) if m.encode() not in data]
        if digest != spec.get("sha256") or missing:
            bad.append(f"{path} sha256={'ok' if digest == spec.get('sha256') else 'MISMATCH'}"
                       + (f" missing_markers={missing}" if missing else ""))
    if unreadable:
        out.append(_degraded(cfg, now, f"{len(unreadable)} patched Paperclip file(s) missing or unreadable (ACL not applied, or "
                                       "the Paperclip tree moved: re-run the ACL step / regenerate the manifest)",
                             unreadable[:cfg["evidence_max"]], "patchfiles"))
    if unsafe:
        out.append(make_finding("patch-file-unsafe", "HIGH", "A patched Paperclip file is not a safe regular file (FIFO, device, symlink in the path, "
                                "foreign owner or oversize): not read", "patch manifest", unsafe[:cfg["evidence_max"]],
                                f"patch-file-unsafe:{len(unsafe)}:{_day(now)}", now, cfg, len(unsafe)))
    if bad:
        out.append(make_finding("patch-undone", "HIGH", "A patched Paperclip file differs from the manifest or lost its LOCAL-PATCH marker",
                                "patch manifest", bad[:cfg["evidence_max"]], f"patch-undone:{len(bad)}:{_day(now)}", now, cfg, len(bad)))
    return out


def _parse_lstart(txt):
    try:                                            # ps prints lstart in the host's local time zone
        return time.mktime(time.strptime(" ".join(txt.split()), "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        return None


def check_paperclip_process(cfg, state, baseline, now, run=sources.run_cmd):
    """the running Paperclip must be the code on disk. Compare the oldest matching process's start time across runs;
    a later start = a restart (MEDIUM, or silent inside a known window). The on-disk files are re-hashed by
    check_patches in every run, so a revert-restart-restore cycle shows up as a restart finding."""
    rc, text = run(cfg["paperclip_proc_cmd"], 30)
    if rc != 0 and not text:
        return [make_finding("source-unreadable", "MEDIUM", "ps failed (Paperclip process check)", "ps", [f"rc={rc}"],
                             f"source-unreadable:ps-paperclip:{_day(now)}", now, cfg)]
    pat = re.compile(cfg["paperclip_proc_pattern"])
    starts = []
    for line in text.splitlines():
        p = line.split(None, 7)
        if len(p) < 8 or not p[0].isdigit():
            continue
        user, args = p[6], p[7]
        if user != cfg["watched_user"] or not pat.search(args):
            continue
        t = _parse_lstart(" ".join(p[1:6]))
        if t is not None:
            starts.append(t)
    out, old = [], state.get("paperclip_start")
    if starts:
        cur = min(starts)
        if not baseline and old is not None and cur > old + 5:
            from .logrules import in_windows
            if not in_windows(cur, cfg.get("known_restart_windows")):
                out.append(make_finding("paperclip-restart", "MEDIUM",
                                        "Paperclip process restarted outside a known maintenance window (running code may differ from disk)",
                                        "ps", [f"previous start={iso_utc(old)}", f"current start={iso_utc(cur)}"],
                                        f"paperclip-restart:{int(cur)}", now, cfg))
        state.set("paperclip_start", cur)
    return out


def iso_utc(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def check_disk(cfg, state, baseline, now, statvfs=None):
    """Y5e: a full disk stops journald and the state writes (MEDIUM < 20 % free, HIGH < 10 %)."""
    out, statvfs = [], statvfs or os.statvfs
    for path in cfg["disk_paths"]:
        try:
            v = statvfs(path)
        except OSError:
            continue
        free = 100.0 * v.f_bavail / v.f_blocks if v.f_blocks else 100.0
        if free < 20:
            out.append(make_finding("disk-free", "HIGH" if free < 10 else "MEDIUM", f"Low free disk space on {path}: {free:.0f}%",
                                    "statvfs", [f"{path} free={free:.1f}%"], f"disk-free:{path}:{'h' if free < 10 else 'm'}:{_day(now)}", now, cfg))
    return out


# ---- vault -----------------------------------------------------------------------------------------------
GENESIS = "0" * 64


def _digest(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_chain(paths, from_genesis=True, first_prev=None, uid=None):
    """Independent re-implementation of vaultd's audit.verify (same digest). Returns (ok, message).
    first_prev: when given, the first record must carry this prev_hash (the last hash of the compressed history).
    The files are opened through acl.open_file (uid = the vault account, None: no owner check): a FIFO, symlink, device,
    foreign owner or oversize file raises acl.Refused instead of blocking or being followed. A file that cannot be opened or
    read (denied, rotated away mid-run, an I/O error) raises OSError: that is no verdict about the chain, so only a real break
    returns (False, message)."""
    prev, n, torn = None, 0, None
    for path in paths:
        with io.TextIOWrapper(acl.open_file(path, uid), encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    if torn:
                        return False, f"{path}:{i}: not JSON"
                    torn = (path, i, hashlib.sha256(line.rstrip("\n").encode()).hexdigest())
                    continue
                if not isinstance(e, dict):
                    return False, f"{path}:{i}: not an audit record"
                if torn:
                    if e.get("event") != "torn-tail-recovered" or e.get("bad_line_sha256") != torn[2]:
                        return False, f"{torn[0]}:{torn[1]}: not JSON"
                    torn = None
                if prev is None:
                    if from_genesis and e.get("prev_hash") != GENESIS:
                        return False, f"{path}:{i}: chain does not start at genesis"
                    if first_prev and e.get("prev_hash") != first_prev:
                        return False, f"{path}:{i}: chain does not continue from the compressed history"
                elif e.get("prev_hash") != prev:
                    return False, f"{path}:{i}: chain broken (prev_hash mismatch)"
                if e.get("hash") != _digest(e):
                    return False, f"{path}:{i}: hash mismatch (record altered)"
                prev, n = e["hash"], n + 1
    return True, f"ok: {n} records" + (" (torn final record)" if torn else "")


def _q(rec):
    keep = {k: rec.get(k) for k in ("time", "agent", "issue", "credential", "reason", "decision", "ceiling", "admin") if k in rec}
    return json.dumps(keep, sort_keys=True)


def vault_rules(recs, cfg, now):
    """Findings from new audit records. Quoted evidence is the JSON of selected fields."""
    out, agg = [], {}

    def add(rule, sev, title, key, rec):
        if key in agg:
            agg[key]["count"] += 1
            if len(agg[key]["evidence"]) < cfg["evidence_max"]:
                agg[key]["evidence"].append(clean(_q(rec), cfg["evidence_chars"]))
            return
        agg[key] = make_finding(rule, sev, title, "vault audit log", [_q(rec)], key, now, cfg)

    stats = {"grant": 0, "deny": 0, "other": 0}
    for r in recs:
        day = _day(now)
        if "_unparsable" in r:
            add("vault-unparsable", "MEDIUM", "Vault audit log has an unparsable line", f"vault-unparsable:{day}", {"reason": r["_unparsable"]})
            continue
        if "admin" in r:
            add("vault-admin", "INFO", "vaultctl owner command", f"vault-admin:{r.get('admin')}:{r.get('time')}", r)
            continue
        dec, ceil, agent, cred = str(r.get("decision", "")), str(r.get("ceiling", "")), r.get("agent"), r.get("credential")
        stats["grant" if dec.startswith("grant") else "deny" if dec.startswith("deny") else "other"] += 1
        if ceil == "judge-lock":
            add("vault-judge-lock", "HIGH", "Judge chose option d: agent locked", f"vault-judge-lock:{agent}:{day}", r)
        elif ceil == "never-grantable":
            add("vault-never-grantable", "HIGH", "Request for a never-grantable credential", f"vault-never:{agent}:{cred}:{day}", r)
        elif ceil == "agent-locked":
            add("vault-locked-agent-request", "MEDIUM", "Locked agent keeps requesting credentials", f"vault-locked:{agent}:{day}", r)
        elif ceil in ("identity", "bad-name", "bad-request") and agent is None:
            add("vault-identity-failure", "MEDIUM", "Vault identity / bad-request failures", f"vault-identity:{day}", r)
        elif dec == "backoff" or ceil in ("loop-guard", "loop-guard-agent"):
            add("vault-loop-guard", "MEDIUM", "Vault loop guard triggered", f"vault-loop-guard:{agent}:{cred}:{day}", r)
        elif ceil == "unknown-agent":
            add("vault-unknown-agent", "MEDIUM", "Unlisted agent asked the vault for a credential", f"vault-unknown-agent:{agent}:{day}", r)
        elif ceil == "approval-mismatch":
            add("vault-approval-mismatch", "MEDIUM", "Follow-up asked for more than the owner approved", f"vault-approval-mismatch:{agent}:{day}", r)
    out.extend(agg.values())
    if recs:
        out.append(make_finding("vault-stats", "INFO", "Vault requests", "vault audit log",
                                [f"grants={stats['grant']} denies={stats['deny']} other={stats['other']}"],
                                f"vault-stats:{int(now)}", now, cfg, sum(stats.values())))
    return out


def _gz_last_hash(path, uid=None):
    """Last record hash of a compressed audit file, None when it cannot be read. Opened through acl.open_file (raises
    acl.Refused when unsafe); the expanded size is capped like the file size, so a gzip bomb is refused too."""
    last, seen = None, 0
    try:
        with acl.open_file(path, uid) as raw, gzip.GzipFile(fileobj=raw) as f:
            while True:
                line = f.readline(1 << 20)
                if not line:
                    break
                seen += len(line)
                if seen > acl.STREAM_CAP:
                    raise acl.Refused(f"{path}: expands past the {acl.STREAM_CAP} byte limit; not read", "oversize")
                try:
                    last = json.loads(line)["hash"]
                except (ValueError, KeyError, TypeError):
                    pass
    except (OSError, EOFError, zlib.error):
        return None
    return last


def check_vault(cfg, state, baseline, now):
    """Every audit file is read through acl.open_file (uid = vault_uid when set): a FIFO, symlink, device, foreign owner or
    oversize file is not read and is MEDIUM 'vault-log-unsafe' (the chain check is then skipped for it, never hung)."""
    path = cfg["vault_audit_log"]
    if not path:                       # no vault on this host (the installer writes it empty): nothing to read
        return []
    files = sources.vault_files(path)
    if not files:
        return [make_finding("source-unreadable", "MEDIUM", "Vault audit log not readable", "vault audit log", [path],
                             f"source-unreadable:vault:{_day(now)}", now, cfg)]
    out, unsafe = [], set()
    try:
        uid = int(str(cfg.get("vault_uid", "")))
    except ValueError:
        uid = None
    # retention gzips older rotated files (not read for the live check): the plain files then start mid-chain, so no genesis check;
    # instead the first plain record must continue from the newest .gz (its last hash is cached by name+size+mtime), and a .gz
    # that vanishes while younger than the retention window is HIGH.
    d, base = os.path.split(path)
    stem, ext = os.path.splitext(base)
    gzs = sorted(glob.glob(os.path.join(d, f"{stem}-*{ext}.gz")))
    seen = state.get("vault_gz", {})
    cur = {}
    for g in gzs:
        try:
            st = os.stat(g)
        except OSError:
            continue
        key = f"{st.st_size}:{int(st.st_mtime)}"
        old = seen.get(os.path.basename(g))
        cur[os.path.basename(g)] = {"key": key, "mtime": st.st_mtime, "last": old["last"] if old and old.get("key") == key else None}
    anchor = None
    if gzs and os.path.basename(gzs[-1]) in cur:
        ent = cur[os.path.basename(gzs[-1])]
        if ent["last"] is None:
            try:
                ent["last"] = _gz_last_hash(gzs[-1], uid)
            except acl.Refused as e:
                unsafe.add(str(e))
        anchor = ent["last"]
        if anchor is None and not unsafe:
            out.append(make_finding("source-unreadable", "MEDIUM", "Newest compressed vault audit file not readable", "vault audit log",
                                    [gzs[-1]], f"source-unreadable:vault-gz:{_day(now)}", now, cfg))
    window = cfg.get("vault_retention_days", 365) * 86400
    for name, ent in seen.items():
        if name not in cur and now - ent.get("mtime", 0) < window:
            out.append(make_finding("vault-audit-missing", "HIGH", "A compressed vault audit file disappeared before its retention ended",
                                    "vault audit log", [name], f"vault-gz-missing:{name}", now, cfg))
            cur[name] = ent                       # keep reminding (dedup) until the retention window has passed
    state.set("vault_gz", cur)
    try:
        ok, msg = verify_chain(files, cfg["vault_verify_from_genesis"] and len(files) >= 1 and not gzs, first_prev=anchor, uid=uid)
    except acl.Refused as e:
        ok, msg = True, ""
        unsafe.add(str(e))
    except OSError as e:                          # denied, rotated away mid-run: the chain was not checked, which is not a break
        ok, msg = True, ""
        out.append(make_finding("source-unreadable", "MEDIUM", "Vault audit log could not be read for the chain check", "vault audit log",
                                [(e.strerror or type(e).__name__) + (f" ({e.filename})" if e.filename else "")], f"source-unreadable:vault-chain:{_day(now)}", now, cfg))
    if not ok:
        out.append(make_finding("vault-chain-broken", "HIGH", "Vault audit log hash chain verification FAILED", "vault audit log",
                                [msg], f"vault-chain:{hashlib.sha256(msg.encode()).hexdigest()[:12]}", now, cfg))
    try:
        recs, rok = sources.read_vault_new(path, state, uid)
    except acl.Refused as e:
        recs, rok = [], False
        unsafe.add(str(e))
    for why in sorted(unsafe):
        out.append(make_finding("vault-log-unsafe", "MEDIUM", "A vault audit file is not safe to read (FIFO, device, symlink, foreign owner "
                                "or oversize): not read", "vault audit log", [why],
                                f"vault-log-unsafe:{hashlib.sha256(why.encode()).hexdigest()[:12]}:{_day(now)}", now, cfg))
    if baseline or not rok:
        return out
    return out + vault_rules(recs, cfg, now)
