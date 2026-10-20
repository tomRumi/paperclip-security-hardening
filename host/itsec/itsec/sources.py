"""Readers for the raw sources. Each takes an injectable runner so tests never touch the host."""
import fnmatch
import glob
import itertools
import json
import os
import pwd
import re
import stat
import subprocess
import threading
import time

from . import acl
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
    """New complete lines of the fallback auth log (at most acl.READ_CAP bytes per run; the offset moves on). Opened through
    acl.open_file: a FIFO, symlink or device in its place is unreadable, never a blocking read."""
    path = cfg["auth_log_fallback"]
    try:
        with acl.open_file(path, None, cap=None) as f:
            st = os.fstat(f.fileno())
            off = state.get("auth_log_offset", {})
            pos = off.get("pos", 0) if off.get("ino") == st.st_ino and off.get("pos", 0) <= st.st_size else 0
            f.seek(pos)
            data = f.read(acl.READ_CAP)
        data = data[: data.rfind(b"\n") + 1]                      # never consume a half-written line
        state.set("auth_log_offset", {"ino": st.st_ino, "pos": pos + len(data)})
        return parse_auth_log(data.decode("utf-8", "replace").splitlines()), True
    except (OSError, acl.Refused):
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


def _read_complete(path, pos, uid=None):
    """The complete lines of `path` from byte `pos` (at most acl.READ_CAP bytes per call; the offset moves on, the rest comes
    next run). Through acl.open_file: a FIFO, a symlink, a device or a foreign owner is acl.Refused, never a blocking read."""
    with acl.open_file(path, uid, cap=None) as f:
        f.seek(pos)
        data = f.read(acl.READ_CAP)
    return data[: data.rfind(b"\n") + 1]


def read_vault_new(path, state, uid=None):
    """New complete JSON records since the stored (inode, offset). Truncation restarts at 0. When the inode changed (rotation),
    the unread tail of the rotated file that still has the stored inode is read first, then the new live file from 0.
    Returns (records, ok). Unparsable lines are returned as {'_unparsable': line}. uid = the vault account (None: no owner
    check). Raises acl.Refused when the log is not a safe regular file."""
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
                    recs += _parse_records(_read_complete(rp, off.get("pos", 0), uid))
                    break
        pos = off.get("pos", 0) if off.get("ino") == st.st_ino and off.get("pos", 0) <= st.st_size else 0
        data = _read_complete(path, pos, uid)
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


WATCH_MAX_OBJECTS = 3000                        # files, directories and links together, per watched tree
GLOB_ENTRIES_PER_OBJECT = 10                    # a glob reads at most this many x watch_max_objects directory entries, match or not
HASH_FILE_CAP = 64 << 20                        # largest file of the watched account that is hashed
HASH_BUDGET = 1 << 30                           # bytes hashed per run; the rest is compared by size and time
_RACY_NS = 2_000_000_000                        # a hash of a file changed less than this ago is not cached (same-tick writes)


def _walk(top, limit):
    """walk_tree with the number of entries seen: (paths, seen, truncated)."""
    paths, seen, stack = [], 0, [top]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = sorted(itertools.islice(it, limit + 1), key=lambda e: e.name)
        except OSError:
            paths.append(d)
            continue
        subdirs = []
        for e in entries:
            if seen >= limit:
                return paths, seen, True
            seen += 1
            try:
                is_dir = e.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            (subdirs if is_dir else paths).append(os.path.join(d, e.name))
        stack.extend(reversed(subdirs))
    return paths, seen, False


def walk_tree(top, limit=WATCH_MAX_OBJECTS):
    """What the watch records below the directory `top`: every entry that is not a plain directory (files, symlinks, also
    symlinks to directories, which are never entered, FIFOs ...) plus every directory that cannot be listed (the caller
    records its own stat signature, so a change is a finding). Entries come in name order, depth first, and each entry seen
    (directories too) counts against `limit`. Returns (paths, truncated): truncated is True when the tree has more than
    `limit` entries (the rest is not looked at). A directory is listed up to `limit` + 1 names, so memory stays bounded; only one
    with more than `limit` entries is looked at in file system order instead of name order (it truncates in any case)."""
    paths, _, truncated = _walk(top, limit)
    return paths, truncated


def under(path, top):
    """path is top or lies below it."""
    return path == top or path.startswith(top.rstrip("/") + "/")


def bounded_glob(pat, limit=WATCH_MAX_OBJECTS):
    """glob.glob(pat) with bounded work. A directory is listed only for a wildcard segment (a plain name is one lstat), the
    whole pattern reads at most GLOB_ENTRIES_PER_OBJECT x `limit` directory entries (a directory is read only as far as
    that), and no more than `limit` matches are carried from one segment to the next. A wildcard does not match a leading
    dot unless the segment starts with one (as glob does). Returns (sorted matches, cut): cut is True when entries or
    matches were left out, whether or not anything matched."""
    if not glob.has_magic(pat):
        return ([pat] if os.path.lexists(pat) else []), False
    left, cut = limit * GLOB_ENTRIES_PER_OBJECT, False
    cur = ["/" if pat.startswith("/") else ""]
    for seg in (x for x in pat.split("/") if x):
        nxt = []
        if glob.has_magic(seg):
            for base in cur:
                if left <= 0:
                    cut = True
                    break
                try:
                    with os.scandir(base or ".") as it:
                        names = [e.name for e in itertools.islice(it, left + 1)]
                except OSError:
                    continue
                if len(names) > left:
                    cut, names = True, names[:left]
                left -= len(names)
                nxt += [os.path.join(base, n) for n in names if fnmatch.fnmatchcase(n, seg) and (seg[0] == "." or n[0] != ".")]
        else:
            nxt = [q for q in (os.path.join(base, seg) for base in cur) if os.path.lexists(q)]
        if len(nxt) > limit:
            cut, nxt = True, sorted(nxt)[:limit]
        cur = nxt
    return sorted(cur), cut


def covers(pat, path):
    """The glob `pat` covers `path`: the glob itself or anything below it."""
    return fnmatch.fnmatchcase(path, pat) or fnmatch.fnmatchcase(path, pat + "/*")


def covering_entries(cfg, path):
    """The watch entries whose globs cover `path`."""
    return [w for w in cfg["watch"] if any(covers(g, path) for g in w["globs"])]


def expand_watch(cfg, problems=None, truncated=None, recorded=()):
    """Expand the watch globs to a dict path -> severity. Globs are expanded by bounded_glob and directories walked by
    walk_tree. A path that cannot even be looked at (EACCES on the path or on a directory above the wildcard) used to vanish
    silently; it is now appended to `problems` as (path, reason). The bound is cfg watch_max_objects per tree for a path
    named without a wildcard, and ONE budget of that many objects per wildcard pattern, shared by all its hits and their walks
    (so a pattern cannot grow with the square of the cap). What is cut off (a tree, or a pattern with more objects than its
    budget, more hits, or one that would read more directory entries than that allows) is appended to `truncated` (a tree:
    its path, a pattern: its static prefix): the caller reports it. The cap limits the DISCOVERY of new entries only:
    `recorded` (the paths already in the state, which the caller looks at by their own path) is what a cut tree or pattern has
    taken so far, and it takes new entries only until recorded and new together reach the cap, so the state stays that
    small. A path named in the config without a wildcard is never cut."""
    out = {}
    limit = cfg.get("watch_max_objects", WATCH_MAX_OBJECTS)
    for w in cfg["watch"]:
        sev = w.get("severity", "HIGH")
        excl = w.get("exclude", [])             # optional patterns, '*' per path segment (see excluded()): files not to watch in this entry
        for pat in w["globs"]:
            wild = glob.has_magic(pat)
            hits, cut = bounded_glob(pat, limit)
            if not hits and problems is not None:
                try:
                    if wild:
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
            left, found = limit, []                         # left: the one budget of a wildcard pattern
            for p in hits:
                if wild:
                    if left <= 0:
                        cut = True
                        break
                    left -= 1
                if os.path.isdir(p) and not os.path.islink(p):
                    paths, seen, tree_cut = _walk(p, left if wild else limit)
                    left -= seen
                    cut = cut or tree_cut
                    found += paths
                else:
                    found.append(p)
            room = None
            if cut:                                         # the pattern (a wildcard) or the tree (a plain path) is cut
                scope = _static_prefix(pat) if wild else hits[0]
                if truncated is not None:
                    truncated.append(scope)
                room = limit - sum(1 for r in recorded if (covers(pat, r) if wild else under(r, scope)))
            for fp in found:
                if fp in out or excluded(fp, excl):
                    continue
                if room is not None and fp not in recorded:
                    room -= 1
                    if room < 0:
                        continue
                out[fp] = sev
    return out


def watched_ids(cfg):
    """(uid, home) of the watched account, from the config (watched_uid, else the account's passwd entry); None where unknown."""
    uid, home = None, None
    try:
        uid = int(str(cfg.get("watched_uid", "")))
    except ValueError:
        pass
    try:
        pw = pwd.getpwnam(cfg["watched_user"])
        uid = pw.pw_uid if uid is None else uid
        home = pw.pw_dir
    except KeyError:
        home = "/home/" + cfg["watched_user"]
    return uid, home.rstrip("/") or None


def _stat_sig(st):
    return f"{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}:{st.st_ino}"


def _stat_form(st):
    return f"stat:{_stat_sig(st)}:{st.st_mode:o}:{st.st_uid}:{st.st_gid}"


def _resolved(path, st):
    """(real, where): the path with the symlinks in its directories resolved (a final link is not followed), and "@<real>"
    when that differs from `path` itself, else ""."""
    real = os.path.join(os.path.realpath(os.path.dirname(path)), os.path.basename(path)) if stat.S_ISLNK(st.st_mode) else os.path.realpath(path)
    return real, (f"@{real}" if real != path else "")


def stat_signature(path):
    """What file_signature gives a file it only compares by size and time; None where the path cannot be looked at."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return _stat_form(st) + _resolved(path, st)[1]


def named_paths(cfg):
    """The watch globs without a wildcard: files and trees the operator named, which the collector looks at before it discovers
    anything."""
    return {g for w in cfg["watch"] for g in w["globs"] if not glob.has_magic(g)}


class Hasher:
    """The content hashes of one collector run. `cache` (path -> "device:inode:size:mtime_ns:ctime_ns:sha256", persisted in the state
    by the caller from `.cache` afterwards) lets a file whose device, inode, size, mtime and ctime are unchanged skip the read (ctime cannot be
    set by the file's owner). A file hashed within _RACY_NS of its last change is recorded under the same key with "racy" in place
    of the digest: never reused as a hash, but it says which stat key the file had when it was last hashed. `budget` bytes may be
    read per run (None: no limit): a file that would go past it is not read and is compared by its stat signature, which is
    reported once (`.skipped`); its record is carried over. `cap` is the largest file of the watched account that is read at all."""

    def __init__(self, cache=None, budget=None, cap=HASH_FILE_CAP, now_ns=None):
        self.old = cache if isinstance(cache, dict) else {}
        self.cache, self.skipped = {}, []
        self.left, self.cap = budget, cap
        self.racy = (now_ns if now_ns is not None else time.time_ns()) - _RACY_NS

    @staticmethod
    def _key(st):
        return f"{st.st_dev}:{st.st_ino}:{st.st_size}:{st.st_mtime_ns}:{st.st_ctime_ns}"

    def lookup(self, path, st):
        entry = self.old.get(path)
        key, _, digest = entry.rpartition(":") if isinstance(entry, str) else ("", "", "")
        if key == self._key(st) and re.fullmatch(r"[0-9a-f]{64}", digest):
            self.cache[path] = entry
            return digest
        return None

    def unchanged_since_hash(self, path):
        """The file has exactly the stat key it was last hashed under (a hash or a "racy" record). False where it has another key
        (it was modified since) or no record at all: nothing shows it is the file that was hashed, so the caller treats it as changed."""
        entry = self.old.get(path)
        key, _, mark = entry.rpartition(":") if isinstance(entry, str) else ("", "", "")
        try:
            return bool(key) and (mark == "racy" or bool(re.fullmatch(r"[0-9a-f]{64}", mark))) and key == self._key(os.lstat(path))
        except OSError:
            return False

    def reserve(self, path, size):
        if self.left is not None and size > self.left:
            self.skipped.append(path)
            if isinstance(self.old.get(path), str):
                self.cache[path] = self.old[path]          # the key of its last hash stays on record until a run can hash it
            return False
        if self.left is not None:
            self.left -= size
        return True

    def store(self, path, st, digest):
        self.cache[path] = f"{self._key(st)}:{digest if st.st_ctime_ns < self.racy else 'racy'}"


def file_signature(path, uid=None, home=None, hasher=None):
    """Content hash when readable, otherwise a stat signature (ctime cannot be set by the file's owner).
    Every file is opened through acl.open_file after its symlinks are resolved once: a later swap, a FIFO, a device, or (for
    a file the watched account controls: it owns it, or it lies under its `home`; uid is the account) a foreign owner or a
    file over hasher.cap gives "refused:<kind>:<meta>" (check_files reports it; an oversize one carries its stat signature too,
    so a change still shows). A directory (one that cannot be listed) is its stat signature. `hasher` (a Hasher) adds the
    hash cache and the per-run byte budget; a file the budget does not cover is its stat signature. Whatever the path
    resolves to when a directory above the file (not the file itself) is a symlink is part of the signature as
    "@<resolved path>": a parent directory swapped for a link to an identical copy is a change, while a path that is legitimately
    behind a link (the operator's `cli/current`) keeps the same signature as long as the link goes the same way."""
    try:
        st = os.lstat(path)
    except OSError:
        return "missing"
    meta = f"{st.st_mode:o}:{st.st_uid}:{st.st_gid}"
    real, where = _resolved(path, st)
    if stat.S_ISLNK(st.st_mode):
        return f"link:{os.readlink(path)}:{meta}{where}"
    stat_sig = _stat_form(st) + where
    if stat.S_ISDIR(st.st_mode):
        return stat_sig
    hasher = hasher or Hasher()
    controlled = uid is not None and (st.st_uid == uid or (home is not None and (path == home or path.startswith(home + "/"))))
    cap = hasher.cap if controlled else acl.STREAM_CAP

    def oversize():
        return f"refused:oversize:{meta}:{_stat_sig(st)}{where}"
    if st.st_size > cap:
        return oversize()
    cached = hasher.lookup(path, st)
    if cached:
        return f"sha256:{cached}:{meta}{where}"
    if not hasher.reserve(path, st.st_size):
        return stat_sig
    try:
        digest = sha256_file(real, owner=uid if controlled else None, cap=cap)
    except acl.Refused as e:
        return oversize() if e.kind == "oversize" else f"refused:{e.kind}:{meta}{where}"
    except OSError:
        return stat_sig
    hasher.store(path, st, digest)
    return f"sha256:{digest}:{meta}{where}"


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
