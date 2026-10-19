"""Readers for the raw sources. Each takes an injectable runner so tests never touch the host."""
import fnmatch
import glob
import json
import os
import re
import subprocess
import threading
import time

from .core import sha256_file


def run_cmd(cmd, timeout=60, env=None):
    """Default runner: (returncode, stdout). Never raises for missing binaries or timeouts (rc 127 / 124)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
        return p.returncode, p.stdout
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired:
        return 124, ""


def _msg(v):
    if isinstance(v, list):                      # journald encodes non-UTF8 messages as byte arrays
        try:
            return bytes(v).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return ""
    return v if isinstance(v, str) else ""


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_journal_json(text):
    """Parse `journalctl -o json` output (str or list of lines) to (events, last_cursor).
    identity comes from journald's trusted fields (_UID, _EXE, _SYSTEMD_UNIT, _SYSTEMD_USER_UNIT, _TRANSPORT, _COMM),
    never from SYSLOG_IDENTIFIER (any process can set that). 'ident' is kept for display only."""
    events, cursor = [], None
    for line in (text.splitlines() if isinstance(text, str) else text):
        try:
            j = json.loads(line)
        except ValueError:
            continue
        if not isinstance(j, dict):
            continue
        try:
            ts = int(j.get("__REALTIME_TIMESTAMP", "0")) / 1e6
        except (TypeError, ValueError):
            ts = 0.0
        sunit, uunit = _msg(j.get("_SYSTEMD_UNIT")), _msg(j.get("_SYSTEMD_USER_UNIT"))
        events.append({"msg": _ANSI.sub("", _msg(j.get("MESSAGE"))),
                       "ident": _msg(j.get("SYSLOG_IDENTIFIER")) or _msg(j.get("_COMM")),
                       "unit": sunit or uunit, "uid": _msg(j.get("_UID")), "exe": _msg(j.get("_EXE")),
                       "sunit": sunit, "uunit": uunit, "transport": _msg(j.get("_TRANSPORT")),
                       "comm": _msg(j.get("_COMM")), "trusted": True, "ts": ts or time.time()})
        cursor = j.get("__CURSOR") or cursor
    return events, cursor


def stream_cmd(cmd, timeout=120, max_lines=50000):
    """read a command's stdout line by line (never the whole output in memory, never an unbounded wait).
    Returns (rc, lines, status), status in ok | truncated (max_lines reached, the process is stopped) | timeout | error."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace")
    except OSError:
        return 127, [], "error"
    fired = threading.Event()

    def _kill():
        fired.set()
        proc.kill()
    timer = threading.Timer(timeout, _kill)
    timer.start()
    lines, status = [], "ok"
    try:
        for line in proc.stdout:
            lines.append(line)
            if len(lines) >= max_lines:
                status = "truncated"
                proc.kill()
                break
    finally:
        timer.cancel()
        proc.stdout.close()
        rc = proc.wait()
    if fired.is_set():
        return 124, lines, "timeout"
    if status == "ok" and rc != 0 and not lines:
        status = "error"
    return rc, lines, status


def stream_from_run(run):
    """Adapter for tests / legacy runners: a (cmd, timeout) -> (rc, text) function as a stream function."""
    def _s(cmd, timeout=120, max_lines=50000):
        rc, out = run(cmd, timeout)
        lines = (out or "").splitlines(True)
        if rc == 124:
            return rc, lines[:max_lines], "timeout"
        if rc != 0 and not lines:
            return rc, [], "error"
        return rc, lines[:max_lines], "truncated" if len(lines) > max_lines else "ok"
    return _s


def read_journal(cfg, state, stream=stream_cmd):
    """New journal entries since the stored cursor, filtered and streamed in cursor batches.
    Returns dict: events, cursor, status (ok | truncated | timeout | error), gap (stored cursor entry no longer exists)."""
    base = list(cfg["journal_cmd"])
    matches = list(cfg.get("journal_matches", []))
    cur = state.get("journal_cursor")
    res = {"events": [], "cursor": cur, "status": "ok", "gap": False}
    if cur:                                                # Y5d: is the entry we stopped at still there?
        _, first, st = stream(base + ["--cursor", cur] + matches, 30, 1)
        if st != "error" and first:
            _, c0 = parse_journal_json(first)
            res["gap"] = bool(c0) and c0 != cur
    for _ in range(max(1, int(cfg.get("journal_max_batches", 4)))):
        cmd = base + (["--after-cursor", cur] if cur else ["--since", cfg["journal_first_run_since"]]) + matches
        rc, lines, status = stream(cmd, cfg.get("journal_timeout_s", 120), cfg.get("journal_batch_lines", 50000))
        evs, c = parse_journal_json(lines)
        res["events"] += evs
        if c:
            cur = res["cursor"] = c
        if status in ("error", "timeout"):
            res["status"] = "ok" if status == "error" and res["events"] else status
            return res
        if status != "truncated":
            res["status"] = "ok"
            return res
        res["status"] = "truncated"                        # another batch follows; still full after the last one = backlog
    return res


_SYSLOG_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+(?:[+-]\d\d:\d\d|Z)|[A-Z][a-z]{2}\s+\d+\s[\d:]{8})\s+\S+\s+(?P<ident>[^\s:\[]+)(?:\[\d+\])?:\s(?P<msg>.*)$")


def parse_auth_log(lines, year=None):
    """/var/log/auth.log (rsyslog) lines to events. Used only when the journal is not readable."""
    events = []
    for line in lines:
        m = _SYSLOG_RE.match(line.rstrip("\n"))
        if not m:
            continue
        raw, ts = m.group("ts"), 0.0
        try:
            if raw[0].isdigit():
                from datetime import datetime
                ts = datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
            else:
                y = year or time.gmtime().tm_year
                ts = time.mktime(time.strptime(f"{y} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")) - time.timezone
        except ValueError:
            ts = time.time()
        events.append({"msg": m.group("msg"), "ident": m.group("ident"), "unit": "", "uid": "", "exe": "", "sunit": "",
                       "uunit": "", "transport": "", "comm": "", "trusted": False, "ts": ts})
    return events


def read_auth_log(cfg, state):
    path = cfg["auth_log_fallback"]
    try:
        st = os.stat(path)
        off = state.get("auth_log_offset", {})
        pos = off.get("pos", 0) if off.get("ino") == st.st_ino and off.get("pos", 0) <= st.st_size else 0
        with open(path, "rb") as f:
            f.seek(pos)
            data = f.read()
        data = data[: data.rfind(b"\n") + 1]                      # never consume a half-written line
        state.set("auth_log_offset", {"ino": st.st_ino, "pos": pos + len(data)})
        return parse_auth_log(data.decode("utf-8", "replace").splitlines()), True
    except OSError:
        return [], False


# ---- ss / ps ---------------------------------------------------------------------------------------------
def parse_ss(text, ephemeral_from=32768):
    """`ss -tlnup` to a sorted list of 'proto addr:port'. Ephemeral UDP listeners are ignored."""
    out = set()
    for line in text.splitlines():
        p = line.split()
        if len(p) < 5 or p[0] not in ("tcp", "udp"):
            continue
        local = p[4]
        addr, _, port = local.rpartition(":")
        if not port.isdigit():
            continue
        if p[0] == "udp" and int(port) >= ephemeral_from:
            continue
        out.add(f"{p[0]} {addr}:{port}")
    return sorted(out)


def is_loopback(entry):
    addr = entry.split(" ", 1)[1].rpartition(":")[0]
    return addr.startswith("127.") or addr in ("[::1]", "::1") or addr.startswith("[::ffff:127.")


def parse_ps(text, user):
    return sorted({p[1] for p in (l.split(None, 1) for l in text.splitlines()) if len(p) == 2 and p[0] == user})


# ---- vault audit log -------------------------------------------------------------------------------------
def _parse_records(data):
    recs = []
    for line in data.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            r = json.loads(line)
            recs.append(r if isinstance(r, dict) else {"_unparsable": line[:200]})
        except ValueError:
            recs.append({"_unparsable": line[:200]})
    return recs


def _read_complete(path, pos):
    with open(path, "rb") as f:
        f.seek(pos)
        data = f.read()
    return data[: data.rfind(b"\n") + 1]


def read_vault_new(path, state):
    """New complete JSON records since the stored (inode, offset). Truncation restarts at 0. When the inode changed (rotation),
    the unread tail of the rotated file that still has the stored inode is read first, then the new live file from 0.
    Returns (records, ok). Unparsable lines are returned as {'_unparsable': line}."""
    try:
        st = os.stat(path)
    except OSError:
        return [], False
    off = state.get("vault_offset", {})
    recs = []
    try:
        if off.get("ino") and off.get("ino") != st.st_ino:
            for rp in vault_files(path):
                try:
                    rst = os.stat(rp)
                except OSError:
                    continue
                if rp != path and rst.st_ino == off["ino"] and 0 <= off.get("pos", 0) <= rst.st_size:
                    recs += _parse_records(_read_complete(rp, off.get("pos", 0)))
                    break
        pos = off.get("pos", 0) if off.get("ino") == st.st_ino and off.get("pos", 0) <= st.st_size else 0
        data = _read_complete(path, pos)
    except OSError:
        return [], False
    state.set("vault_offset", {"ino": st.st_ino, "pos": pos + len(data)})
    return recs + _parse_records(data), True


def vault_files(path):
    """Rotated files (audit-*.jsonl, name order = oldest first) then the live one."""
    d, base = os.path.split(path)
    stem, ext = os.path.splitext(base)
    return sorted(glob.glob(os.path.join(d, f"{stem}-*{ext}"))) + ([path] if os.path.exists(path) else [])


# ---- files / users / groups -------------------------------------------------------------------------------
def _static_prefix(pat):
    """Longest leading path of a glob pattern without wildcard characters."""
    parts, keep = pat.split("/"), []
    for part in parts:
        if glob.has_magic(part):
            break
        keep.append(part)
    return "/".join(keep) or "/"


def excluded(path, patterns):
    """Per-segment match: '*' never crosses '/', so a pattern hides exactly that file, never anything below it."""
    ps = path.split("/")
    return any(len(q := x.split("/")) == len(ps) and all(fnmatch.fnmatchcase(a, b) for a, b in zip(ps, q)) for x in patterns)


def expand_watch(cfg, problems=None):
    """Expand the watch globs to a dict path -> severity. Directories are walked (max 3000 files).
    a path that cannot even be looked at (EACCES on the path or on a directory above the wildcard) used to vanish
    silently; it is now appended to `problems` as (path, reason)."""
    out = {}
    for w in cfg["watch"]:
        sev = w.get("severity", "HIGH")
        excl = w.get("exclude", [])             # optional patterns, '*' per path segment (see excluded()): files not to watch in this entry
        for pat in w["globs"]:
            hits = sorted(glob.glob(pat))
            if not hits and problems is not None:
                try:
                    if glob.has_magic(pat):
                        pre = _static_prefix(pat)
                        os.lstat(pre)
                        if os.path.isdir(pre) and not os.access(pre, os.R_OK | os.X_OK):
                            raise PermissionError(13, "not listable", pre)
                    else:
                        os.lstat(pat)
                except PermissionError:
                    problems.append((pat, "permission denied (no ACL / traversal on the path)"))
                except OSError:
                    pass                                    # simply does not exist (yet): not a degradation
            for p in hits:
                if os.path.isdir(p) and not os.path.islink(p):
                    if not os.access(p, os.R_OK | os.X_OK):
                        out.setdefault(p, sev)          # cannot list it: watch the directory's own stat signature
                        continue
                    n = 0
                    for root, _, files in os.walk(p):
                        for fn in files:
                            fp = os.path.join(root, fn)
                            if not excluded(fp, excl):
                                out.setdefault(fp, sev)
                            n += 1
                            if n >= 3000:
                                break
                elif not excluded(p, excl):
                    out.setdefault(p, sev)
    return out


def file_signature(path):
    """Content hash when readable, otherwise a stat signature (ctime cannot be set by the file's owner)."""
    try:
        st = os.lstat(path)
    except OSError:
        return "missing"
    meta = f"{st.st_mode:o}:{st.st_uid}:{st.st_gid}"
    if os.path.islink(path):
        return f"link:{os.readlink(path)}:{meta}"
    try:
        return f"sha256:{sha256_file(path)}:{meta}"
    except OSError:
        return f"stat:{st.st_size}:{int(st.st_mtime)}:{int(st.st_ctime)}:{st.st_ino}:{meta}"


def parse_passwd(path):
    users = {}
    try:
        with open(path) as f:
            for line in f:
                p = line.rstrip("\n").split(":")
                if len(p) >= 7:
                    users[p[0]] = [p[2], p[3], p[6]]
    except OSError:
        return None
    return users


def parse_group(path):
    groups = {}
    try:
        with open(path) as f:
            for line in f:
                p = line.rstrip("\n").split(":")
                if len(p) >= 4:
                    groups[p[0]] = [p[2], sorted(m for m in p[3].split(",") if m)]
    except OSError:
        return None
    return groups
