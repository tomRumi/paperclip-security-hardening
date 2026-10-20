"""Shared pieces: findings, state file, config, text sanitising. No LLM anywhere in this module."""
import json
import os
import re
import tempfile
import time
import hashlib

from . import acl

SEVERITIES = ("INFO", "MEDIUM", "HIGH")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

DEFAULT_CONFIG = {
    "state_dir": "/var/lib/itsec",
    "admin_user": "admin",
    "watched_user": "paperclip",
    "journal_cmd": ["journalctl", "-o", "json", "--no-pager", "-q"],
    # filtered at the source. Fields in a group are ANDed, "+" separates ORed groups. Trusted _-fields only.
    "journal_matches": [
        "_SYSTEMD_UNIT=ssh.service", "+", "_SYSTEMD_UNIT=sshd.service", "+", "_SYSTEMD_UNIT=vaultd.service", "+",
        "_SYSTEMD_UNIT=fail2ban.service", "+",
        "_EXE=/usr/lib/cargo/bin/sudo", "+", "_EXE=/usr/bin/sudo.ws", "+", "_EXE=/usr/bin/su", "+",
        "_SYSTEMD_USER_UNIT=paperclipai.service", "+", "_TRANSPORT=kernel", "+", "_COMM=bwrap", "+",
        "_SYSTEMD_UNIT=user@1000.service", "_EXE=/usr/lib/systemd/systemd"],
    "journal_batch_lines": 50000,           # one streamed batch; a batch that fills up is cut off and the cursor kept
    "journal_max_batches": 4,
    "journal_timeout_s": 120,
    "journal_backlog_high_runs": 3,         # consecutive runs with an unfinished backlog before it becomes HIGH
    "journal_first_run_since": "-3d",
    "auth_log_fallback": "/var/log/auth.log",
    "failed_login_burst": 10,
    "ufw_summary_min": 1,
    "vault_audit_log": "/var/log/vault/audit.jsonl",
    "watch_max_objects": 3000,              # files, directories and links per watched tree; more is cut off (HIGH watch-truncated): new entries are then not discovered, recorded paths are still checked
    "hash_budget_bytes": 1 << 30,           # bytes hashed per collector run; beyond it files are compared by size and time (MEDIUM hash-budget-exceeded)
    "hash_file_cap_bytes": 64 << 20,        # largest file of the watched account that is hashed; a bigger one is HIGH watch-unsafe (oversize)
    "findings_retention_days": 90,          # day files older than this are deleted by itsec-collect; 0 = keep forever
    "vault_verify_from_genesis": True,
    # nothing under /home is ever executed. Patched files are checked in-process against a root-owned manifest.
    "patch_manifest": "/etc/itsec/patch-manifest.json",
    "patch_manifest_owner_uid": 0,
    "watched_uid": "1000",
    "vault_uid": "",                        # uid of the vault service user; empty = only the unit name is required
    "sshd_units": ["ssh.service", "sshd.service"],
    "alert_cap_per_run": 10,                # new HIGH issues per run; the overflow becomes one aggregate issue
    "disk_paths": ["/", "/var/log"],
    "paperclip_proc_cmd": ["ps", "-eo", "pid=,lstart=,user:32=,args="],
    "paperclip_proc_pattern": "\\bpaperclipai\\b",
    "known_restart_windows": [],            # [["2026-10-13T20:00:00Z", "2026-10-13T21:00:00Z"], ...] planned maintenance
    "ss_cmd": ["ss", "-tlnup"],
    "ps_cmd": ["ps", "-eo", "user:32=,comm="],
    "ignore_udp_ephemeral_from": 32768,
    "expected_process_patterns": [
        "^(bash|sh|dash|zsh|node|npm|npx|python3?|claude|git|ssh|ollama|hermes|paperclipai|bwrap|tmux|"
        "sleep|cat|ls|grep|sed|awk|tail|head|curl|env|timeout|systemd|\\(sd-pam\\)|sd-pam|ps|ss|"
        "uv|pip3?|rg|jq|make|gcc|cc1|ld|tsc|vite|esbuild|playwright.*|chrome.*|chromium.*|headless_shell|"
        "MainThread|\\.?node.*|ThreadPoolForeg|gh|qmd|bun)$"
    ],
    "dedup_hours": 24,
    "evidence_max": 5,
    "evidence_chars": 300,
    "watch": [],
    # alert_company_id / alert_token_file are optional: a separate ITSec company and a low-privilege user token
    # (OWNER DECISION PENDING, see INSTALL.md). Unset = company_id / token_file are used.
    "paperclip": {"base_url": "http://127.0.0.1:3100", "company_id": "",
                  "token_file": "/etc/itsec/paperclip-token", "assignee_user_id": "",
                  "alert_company_id": "", "alert_token_file": "", "board_user_id": "",
                  "hmac_key_file": "", "alert_recheck_days": 7},
    "notifier": "paperclip",
    # "notifier": "plugin": alerts and a heartbeat go to the Security hardening plugin's webhook, signed with the key in
    # key_file (written by host/install/install-watchdog.sh --enrol; no Paperclip key on this host).
    "plugin": {"url": "", "install_id": "", "key_file": "${CREDENTIALS_DIRECTORY}/watchdog-key", "openssl": "openssl",
               "version": ""},
    "claude": {"command": "claude", "model": "", "timeout_s": 180, "token_file": ""},
}


def deep_merge(base, over):
    out = dict(base)
    for k, v in over.items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def load_config(path=None):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        with open(path) as f:
            cfg = deep_merge(cfg, json.load(f))
    return cfg


def expand_env(s):
    """Expand $VAR / ${VAR} (e.g. ${CREDENTIALS_DIRECTORY}) in a config path."""
    return os.path.expandvars(s) if isinstance(s, str) else s


# ---- text safety -----------------------------------------------------------------------------------
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏ -‮⁦-⁩﻿]")


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def clean(text, limit=300):
    """Strip control/format characters, collapse newlines, cap length. Used for every evidence string."""
    text = _ANSI.sub("", str(text)).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = _CTRL.sub("", text)
    return text if len(text) <= limit else text[:limit] + "...[cut]"


def now_ts():
    return time.time()


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def make_finding(rule, severity, title, source, evidence=(), dedup_key=None, ts=None, cfg=None, count=1):
    assert severity in SEV_RANK, severity
    cfg = cfg or DEFAULT_CONFIG
    ev = [clean(e, cfg["evidence_chars"]) for e in list(evidence)[: cfg["evidence_max"]]]
    return {"ts": iso(ts if ts is not None else now_ts()), "rule": rule, "severity": severity,
            "title": clean(title, 200), "source": source, "evidence": ev, "count": count,
            "dedup_key": dedup_key or f"{rule}"}


# ---- state -----------------------------------------------------------------------------------------
class State:
    """JSON state in state_dir (the only writable place). Atomic replace. Missing or corrupt file = fresh,
    baseline mode (a corrupt state is itself reported by the collector)."""

    def __init__(self, state_dir):
        self.dir = state_dir
        self.path = os.path.join(state_dir, "state.json")
        self.data = {}
        self.corrupt = False
        self.fresh = True
        try:
            with open(self.path) as f:
                self.data = json.load(f)
            self.fresh = False
        except FileNotFoundError:
            pass
        except (ValueError, OSError):
            self.corrupt = True

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = value

    def save(self):
        os.makedirs(self.dir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".state-")
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=1, sort_keys=True)
        os.replace(tmp, self.path)


def sha256_file(path, chunk=1 << 20, owner=None, cap=None):
    """sha256 of a file, opened through acl.open_file (no symlink in the path, components owned by `owner` or root, `owner`
    None: no owner check; a regular file of at most `cap` bytes, default acl.STREAM_CAP; a FIFO never blocks). Raises
    acl.Refused for anything else, also for a file that grows past the cap while it is read; PermissionError when the account
    may not read it."""
    cap = acl.STREAM_CAP if cap is None else cap
    h = hashlib.sha256()
    with acl.open_file(path, owner, cap) as f:
        total = 0
        while True:
            b = f.read(chunk)
            if not b:
                return h.hexdigest()
            total += len(b)
            if total > cap:
                raise acl.Refused(f"{path}: grew past the {cap} byte limit while it was read", "oversize")
            h.update(b)


# ---- findings store (the day's findings, read by the report) -----------------------------------------
def findings_dir(state_dir):
    return os.path.join(state_dir, "findings")


def append_findings(state_dir, findings):
    if not findings:
        return
    d = findings_dir(state_dir)
    os.makedirs(d, exist_ok=True)
    for f in findings:
        with open(os.path.join(d, f["ts"][:10] + ".jsonl"), "a") as fh:
            fh.write(json.dumps(f, sort_keys=True) + "\n")


def prune_findings(state_dir, keep_days, now=None):
    """Delete findings/YYYY-MM-DD.jsonl day files older than keep_days (by the date in the name; keep_days <= 0 keeps all).
    Only exact day-file names are touched. Returns the number of files removed."""
    if not keep_days or keep_days <= 0:
        return 0
    cutoff = time.strftime("%Y-%m-%d", time.gmtime((now if now is not None else now_ts()) - keep_days * 86400))
    d = findings_dir(state_dir)
    removed = 0
    try:
        names = os.listdir(d)
    except OSError:
        return 0
    for name in names:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.jsonl", name) and name[:10] < cutoff:
            try:
                os.remove(os.path.join(d, name))
                removed += 1
            except OSError:
                pass
    return removed


def read_findings(state_dir, since_iso, until_iso="9999"):
    out = []
    d = findings_dir(state_dir)
    if not os.path.isdir(d):
        return out
    for name in sorted(os.listdir(d)):
        if not name.endswith(".jsonl") or name[:10] < since_iso[:10] or name[:10] > until_iso[:10]:
            continue
        with open(os.path.join(d, name)) as fh:
            for line in fh:
                try:
                    f = json.loads(line)
                except ValueError:
                    continue
                if since_iso <= f.get("ts", "") <= until_iso:
                    out.append(f)
    return out
