import _bootstrap  # noqa: F401
import json
from pathlib import Path
import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from itsec import checks
from itsec.core import load_config, State

T0 = 1760335200.0   # 2025-10-13 06:00:00 UTC


# journald's trusted fields for the genuine senders on this host (what a real entry carries)
TRUST = {
    "sshd": {"sunit": "ssh.service", "uid": "0", "exe": "/usr/lib/openssh/sshd-session"},
    "sudo": {"uid": "1000", "exe": "/usr/lib/cargo/bin/sudo"},
    "su": {"uid": "1000", "exe": "/usr/bin/su"},
    "node": {"uunit": "paperclipai.service", "sunit": "user@1000.service", "uid": "1000", "exe": "/usr/bin/node"},
    "vaultd": {"sunit": "vaultd.service", "uid": "998", "exe": "/usr/bin/python3"},
    "fail2ban-server": {"sunit": "fail2ban.service", "uid": "0", "exe": "/usr/bin/python3"},
    "kernel": {"transport": "kernel", "uid": "0"},
    "bwrap": {"comm": "bwrap", "uid": "1000", "exe": "/usr/bin/bwrap"},
    "systemd-user": {"sunit": "user@1000.service", "uid": "1000", "exe": "/usr/lib/systemd/systemd"},
}
TRUST_BY_UNIT = {"ssh.service": "sshd", "vaultd.service": "vaultd", "paperclipai.service": "node", "fail2ban.service": "fail2ban-server"}
FIELDS = ("uid", "exe", "sunit", "uunit", "transport", "comm")


def make_cfg(tmp, **over):
    cfg = load_config()
    cfg.update({"state_dir": tmp, "vault_audit_log": tmp + "/audit.jsonl", "auth_log_fallback": tmp + "/auth.log",
                "patch_manifest": tmp + "/patch-manifest.json", "patch_manifest_owner_uid": os.getuid(),
                "disk_paths": [], "watch": []})
    cfg.update(over)
    return cfg


def trust_for(ident, unit=""):
    return dict(TRUST.get(ident) or TRUST.get(TRUST_BY_UNIT.get(unit, ""), {}))


def jline(msg, ident="sshd", unit="ssh.service", ts=T0, cursor="c1", **fields):
    """A journald JSON line with the trusted fields of the genuine sender (override with _UID=... style kwargs: uid=...)."""
    t = trust_for(ident, unit)
    t.update(fields)
    j = {"MESSAGE": msg, "SYSLOG_IDENTIFIER": ident, "__REALTIME_TIMESTAMP": str(int(ts * 1e6)), "__CURSOR": cursor}
    for k, name in (("uid", "_UID"), ("exe", "_EXE"), ("sunit", "_SYSTEMD_UNIT"), ("uunit", "_SYSTEMD_USER_UNIT"),
                    ("transport", "_TRANSPORT"), ("comm", "_COMM")):
        if t.get(k):
            j[name] = t[k]
    return json.dumps(j)


def ev(msg, ident="sshd", unit="", ts=T0, **fields):
    e = {"msg": msg, "ident": ident, "unit": unit, "ts": ts, "trusted": True}
    e.update({k: "" for k in FIELDS})
    e.update(trust_for(ident, unit))
    e.update(fields)
    return e


class FakeRun:
    """Maps the first word of the command (or its basename) to (rc, stdout)."""

    def __init__(self, table):
        self.table, self.calls = table, []

    def __call__(self, cmd, timeout=60, env=None):
        self.calls.append(cmd)
        key = cmd[0].split("/")[-1]
        return self.table.get(key, (127, ""))


class FakeNotifier:
    name = "fake"

    def __init__(self, ok=True):
        self.sent, self.ok = [], ok

    def send(self, alert):
        if self.ok:
            self.sent.append(alert)
        return self.ok, "fake"


def write_chain(path, records, tamper=None):
    prev, lines = checks.GENESIS, []
    for r in records:
        e = dict(r, prev_hash=prev)
        e["hash"] = checks._digest(e)
        prev = e["hash"]
        lines.append(e)
    if tamper:
        tamper(lines)
    with open(path, "w") as f:
        for e in lines:
            f.write(json.dumps(e, sort_keys=True) + "\n")


class FakePaperclip:
    """Local HTTP server: POST /api/companies/<id>/issues (recorded, stored) and GET /api/issues/<id>."""

    def __init__(self, status=201):
        self.requests, self.status, self.issues = [], status, {}
        self.activity = {}                                  # issue id -> activity rows (newest first); missing = 403
        self.reply = None                                   # optional override: body -> issue dict
        outer = self

        class H(BaseHTTPRequestHandler):
            def _send(self, code, obj):
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(obj).encode())

            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
                outer.requests.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                if outer.reply:
                    issue = outer.reply(body)
                else:
                    iid = f"uuid-{len(outer.requests)}"
                    issue = {"id": iid, "identifier": f"ENG-{40 + len(outer.requests)}", "companyId": "co-1", "title": body.get("title"),
                             "description": body.get("description"), "status": body.get("status")}
                    outer.issues[iid] = issue
                self._send(outer.status, issue)

            def do_GET(self):
                outer.requests.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": None, "method": "GET"})
                if self.path.endswith("/activity"):
                    iid = self.path.rsplit("/", 2)[-2]
                    return self._send(200, outer.activity[iid]) if iid in outer.activity else self._send(403, {"error": "forbidden"})
                iid = self.path.rsplit("/", 1)[-1]
                if iid in outer.issues:
                    self._send(200, outer.issues[iid])
                else:
                    self._send(404, {"error": "not found"})

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def posts(self):
        return [r for r in self.requests if r.get("method") != "GET"]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def make_patch_fixture(d, cfg):
    """Two 'patched Paperclip files' plus a matching manifest (owner = the test user). Returns the two paths."""
    import hashlib
    f1, f2 = d + "/agents.js", d + "/heartbeat.js"
    put(f1, "a\n// LOCAL-PATCH 0002\n")
    put(f2, "x\n// LOCAL-PATCH 0003\n")
    m = {p: {"sha256": hashlib.sha256(Path(p).read_bytes()).hexdigest(), "markers": [mk]}
         for p, mk in ((f1, "// LOCAL-PATCH 0002"), (f2, "// LOCAL-PATCH 0003"))}
    put(cfg["patch_manifest"], json.dumps(m))
    os.chmod(cfg["patch_manifest"], 0o644)
    return f1, f2


def put(path, text, mode="w"):
    with open(path, mode) as f:
        f.write(text)


def open_read(path):
    with open(path) as f:
        return f.read()


AGENT = "00000000-0000-0000-0000-0000000000a1"


def upd(actor_type, actor_id, to, frm="in_progress"):
    """Activity row shaped like GET /api/issues/{id}/activity (live ENG-107/ENG-120): a status change."""
    return {"actorType": actor_type, "actorId": actor_id, "agentId": actor_id if actor_type == "agent" else None,
            "action": "issue.updated", "entityType": "issue", "createdAt": "2026-10-14T19:07:12.280Z",
            "details": {"status": to, "changes": {"status": {"to": to, "from": frm}}, "_previous": {"status": frm}}}


def comment(actor_type, actor_id):
    return {"actorType": actor_type, "actorId": actor_id, "agentId": actor_id if actor_type == "agent" else None,
            "action": "issue.comment_added", "entityType": "issue", "details": {"commentId": "c1"}}


class FakeWebhook:
    """Local HTTP server standing in for the plugin webhook: records raw body and headers; answers `status` with
    `reply` (JSON)."""

    def __init__(self, status=200, reply=None):
        self.requests, self.status, self.reply = [], status, reply or {"deliveryId": "d1", "status": "success"}
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(n)
                outer.requests.append({"path": self.path, "raw": raw, "headers": {k.lower(): v for k, v in self.headers.items()}})
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(outer.reply).encode())

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
