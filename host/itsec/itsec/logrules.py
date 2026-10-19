"""Deterministic detection over normalised log events. No LLM, no network. Event = dict with
msg, ident, unit, ts (epoch seconds). Everything attacker-controlled (usernames, URLs, messages) only ever
ends up in a finding's quoted 'evidence' strings."""
import collections
import ipaddress
import json
import os
import re
import time

from .core import make_finding, clean

RULES_PATH = os.path.join(os.path.dirname(__file__), "rules.json")


def load_rules(path=RULES_PATH, watched_user="paperclip", cfg=None):
    """Compile rules.json. 'match' (a dict, or a list of dicts = OR) is checked against journald's trusted fields
    (uid, exe, sunit, uunit, transport, comm); '{watched_uid}' / '{vault_uid}' are filled from the config and a key
    whose value ends up empty is dropped. 'fallback_from' is the only identity test for auth.log events, which have
    no trusted fields (the fallback is unverified and flagged as such)."""
    cfg = cfg or {}
    subst = {"{watched_uid}": str(cfg.get("watched_uid", "1000")), "{vault_uid}": str(cfg.get("vault_uid", ""))}

    def fill(v):
        for k, x in subst.items():
            v = v.replace(k, x)
        return v

    with open(path) as f:
        raw = json.load(f)["rules"]
    rules = []
    for r in raw:
        r = dict(r)
        r["_re"] = re.compile(r["pattern"].replace("{watched_user}", re.escape(watched_user)))
        m = r.get("match") or []
        m = [m] if isinstance(m, dict) else m
        alts = []
        for alt in m:
            norm = {}
            for k, v in alt.items():
                vs = [fill(x) for x in (v if isinstance(v, list) else [v])]
                vs = [x for x in vs if x != ""]
                if vs:
                    norm[k] = vs
            alts.append(norm)
        r["_match"] = alts
        r["_fallback"] = re.compile(r["fallback_from"]) if r.get("fallback_from") else None
        rules.append(r)
    return rules


def _identity_ok(r, ev):
    if not ev.get("trusted", True):
        return bool(r["_fallback"] and r["_fallback"].search(ev.get("ident") or ""))
    if not r["_match"]:
        return True
    return any(all(ev.get(k, "") in vs for k, vs in alt.items()) for alt in r["_match"])


def in_windows(ts, windows):
    for w in windows or []:
        try:
            lo = time.mktime(time.strptime(w[0], "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
            hi = time.mktime(time.strptime(w[1], "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
        except (ValueError, IndexError, TypeError):
            continue
        if lo <= ts <= hi:
            return True
    return False


def _day(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


class _Agg:
    """One finding per dedup key per run (count + first few quoted evidence lines)."""

    def __init__(self, cfg):
        self.cfg, self.items = cfg, collections.OrderedDict()

    def add(self, rule, sev, title, source, evidence, key, ts):
        it = self.items.get(key)
        if it is None:
            it = self.items[key] = dict(rule=rule, sev=sev, title=title, source=source, ev=[], key=key, ts=ts, n=0)
        it["n"] += 1
        it["ev"].append(evidence)

    def findings(self):
        return [make_finding(i["rule"], i["sev"], i["title"], i["source"], i["ev"], i["key"], i["ts"], self.cfg, i["n"])
                for i in self.items.values()]


def apply_pattern_rules(events, rules, cfg, agg):
    for ev in events:
        for r in rules:
            m = r["_re"].search(ev["msg"])
            if not m or not _identity_ok(r, ev):
                continue
            if r.get("respect_windows") and in_windows(ev["ts"], cfg.get("known_restart_windows")):
                continue
            fields = {k: clean(v or "", 80) for k, v in m.groupdict().items()}
            key = r["dedup"].format(rule=r["id"], day=_day(ev["ts"]), **fields)
            agg.add(r["id"], r["severity"], r["title"], r["source"], ev["msg"], key, ev["ts"])
            if r.get("stop"):
                break


# ---- sshd ------------------------------------------------------------------------------------------------
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
RE_ACCEPT = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>.+) from " + _IP + r" port (?P<port>\d+)(?: ssh2)?(?::.*)?$")
# Greedy usernames anchored at the end: text inside a username cannot change the attributed address.
RE_FAILS = [
    re.compile(r"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>.+) from " + _IP + r" port \d+(?: ssh2)?$"),
    re.compile(r"^Invalid user (?P<user>.*) from " + _IP + r"(?: port \d+)?$"),
    re.compile(r"^Connection closed by (?:invalid|authenticating) user (?P<user>.+) " + _IP + r" port \d+ \[preauth\]$"),
    re.compile(r"^maximum authentication attempts exceeded for (?:invalid user )?(?P<user>.+) from " + _IP + r" port \d+(?: ssh2)?(?: \[preauth\])?$"),
]


def _valid_ip(s):
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def is_sshd(ev, cfg=None):
    """trusted events need the sshd unit and uid 0 (a process of the watched user cannot be that). auth.log events
    (fallback) only have a forgeable tag; they are accepted for alerting but never used to learn addresses."""
    if not ev.get("trusted", True):
        return (ev.get("ident") or "") in ("sshd", "sshd-session")
    units = (cfg or {}).get("sshd_units", ["ssh.service", "sshd.service"])
    return ev.get("sunit", ev.get("unit", "")) in units and ev.get("uid", "0") == "0"


def ssh_rules(events, cfg, state, baseline, agg):
    """New-IP success (HIGH), admin login (MEDIUM), failed-login burst per IP (MEDIUM).
    seen_ips is learned in baseline mode and extended after each alert."""
    seen = state.get("ssh_seen_ips", {})
    fails = collections.defaultdict(list)
    for ev in events:
        if not is_sshd(ev, cfg):
            continue
        learn = ev.get("trusted", True)
        msg = ev["msg"]
        m = RE_ACCEPT.match(msg)
        if m:
            ip = _valid_ip(m.group("ip"))
            if not ip:
                continue
            user = m.group("user")
            if baseline:
                if learn:
                    seen.setdefault(ip, ev["ts"])
                continue
            if ip not in seen:
                agg.add("ssh-new-ip", "HIGH", "Successful SSH login from an address not seen before", "journal/auth.log (sshd)",
                        msg, f"ssh-new-ip:{ip}", ev["ts"])
                if learn:
                    seen[ip] = ev["ts"]
            if user == cfg["admin_user"]:
                agg.add("admin-login", "MEDIUM", f"Login as {cfg['admin_user']} (maintenance account)", "journal/auth.log (sshd)",
                        msg, f"admin-login:{ip}:{_day(ev['ts'])}", ev["ts"])
            continue
        for rx in RE_FAILS:
            m = rx.match(msg)
            if m:
                ip = _valid_ip(m.group("ip"))
                if ip:
                    fails[ip].append((ev["ts"], msg))
                break
    if not baseline:
        for ip, lst in fails.items():
            if len(lst) >= cfg["failed_login_burst"]:
                ts = lst[0][0]
                for _, msg in lst[: cfg["evidence_max"]]:
                    agg.add("ssh-fail-burst", "MEDIUM", f"Failed SSH login burst from {ip}", "journal/auth.log (sshd)",
                            msg, f"ssh-fail-burst:{ip}:{_day(ts)}", ts)
                agg.items[f"ssh-fail-burst:{ip}:{_day(ts)}"]["n"] = len(lst)
    state.set("ssh_seen_ips", seen)


# ---- ufw -------------------------------------------------------------------------------------------------


def ufw_summary(events, cfg, agg_list, now):
    total = 0
    by_port = collections.defaultdict(collections.Counter)
    for ev in events:
        if "[UFW BLOCK]" not in ev["msg"] or ev.get("transport", "kernel") != "kernel":
            continue
        m = re.search(r"\bSRC=(\S+)", ev["msg"])
        proto = re.search(r"\bPROTO=(\S+)", ev["msg"])
        dpt = re.search(r"\bDPT=(\d+)", ev["msg"])
        if not m:
            continue
        total += 1
        by_port[f"{dpt.group(1) if dpt else '?'}/{proto.group(1) if proto else '?'}"][m.group(1)] += 1
    if total >= cfg["ufw_summary_min"] and total:
        lines = []
        for port, c in sorted(by_port.items(), key=lambda kv: -sum(kv[1].values()))[: cfg["evidence_max"]]:
            top, n = c.most_common(1)[0]
            lines.append(f"dst {port}: {sum(c.values())} blocked from {len(c)} sources (top {top} x{n})")
        agg_list.append(make_finding("ufw-blocks", "INFO", f"ufw blocked {total} packets", "journal (kernel/ufw)", lines,
                                     f"ufw-blocks:{int(now)}", now, cfg, total))


def run_log_rules(events, rules, cfg, state, baseline, now):
    """Return findings from a batch of events. In baseline mode only the learning side effects happen."""
    agg = _Agg(cfg)
    extra = []
    if not baseline:
        apply_pattern_rules(events, rules, cfg, agg)
    ssh_rules(events, cfg, state, baseline, agg)
    if not baseline:
        ufw_summary(events, cfg, extra, now)
    return agg.findings() + extra
