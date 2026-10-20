#!/usr/bin/env bash
# install-watchdog.sh: one-line installer for the Paperclip watchdog (host/itsec), run by an admin with sudo.
#
#   sudo bash install-watchdog.sh --paperclip http://HOST:3100 --enrol CODE     install (or update) and enrol
#   sudo bash install-watchdog.sh                                              update an installed watchdog
#   sudo bash install-watchdog.sh --uninstall                                  remove service, account and files
#
# Options:
#   --paperclip URL   Paperclip as this host reaches it (http(s)://host[:port]); needed on the first install
#   --enrol CODE      one-time code from the plugin's Hardening page (15 minutes, single use). Never printed.
#   --base-url URL    where the watchdog bundle is downloaded from (default: the GitHub release of this version;
#                     also $PCSH_BASE_URL). Only https:// (file:// only together with --prefix, for tests).
#   --watched-user U  the account Paperclip runs as (default: paperclip; the plugin's line passes it); written into a NEW config only
#   --admin-user U    your admin account, whose logins the watchdog reports as maintenance (default: the account that ran
#                     sudo, $SUDO_USER; without either the example value "admin" stays); written into a NEW config only
#   --prefix DIR      install into a fake root for tests: no useradd/systemctl/chown, prints "would run: ..." instead
#   --uninstall       remove everything this script installed (tells the plugin first, best effort)
#
# What it does (host/itsec/INSTALL.md is the reference for what ends up on the host):
#   1. downloads the bundle from the official release and checks it against the sha256 pinned below (written by
#      scripts/release.sh); a mismatch stops before anything is installed;
#   2. creates the system user `itsec` (no shell, no sudo; groups adm, systemd-journal, vaultaudit) and installs the
#      code root-owned under /opt/itsec, the config under /etc/itsec, the units under /etc/systemd/system;
#   3. generates the watchdog's Ed25519 key (/etc/itsec/watchdog-key.pem, root 0600, handed to the units with
#      LoadCredential) and enrols its public key with the Security hardening plugin using the one-time code. No
#      Paperclip board or agent key is created or stored on this host;
#   4. gives the itsec user read access (setfacl ACL entries, through /opt/itsec/bin/itsec-acl, which refuses symlinks) to the
#      files it watches in the watched user's home and writes the patch manifest /etc/itsec/patch-manifest.json (hashes of the
#      patched Paperclip files). The paths are listed in /etc/itsec/acl-paths before they are granted; --uninstall removes them
#      (an entry it could not remove is printed and kept in /root/itsec-acl-paths.left, outside the directory it deletes);
#   5. runs the first collector pass (baseline; it also sends the first heartbeat) and enables the timers (the weekly Lynis one only if lynis is installed).
# Not automated (printed at the end): fail2ban. Idempotent: running it again updates the code and units, refreshes the
# read access and the manifest (do this after a Paperclip update) and keeps the key, the install id and the config.
set -euo pipefail
umask 022

VERSION="__VERSION__"
BUNDLE_SHA256="__BUNDLE_SHA256__"
DEFAULT_BASE_URL="__BASE_URL__"
PLUGIN_KEY="paperclip-security-hardening"
BUNDLE="paperclip-watchdog-${VERSION}.tar.gz"
TIMERS=(itsec-collect.timer itsec-report.timer itsec-lynis.timer)
UNITS=(itsec-collect.service itsec-collect.timer itsec-report.service itsec-report.timer itsec-lynis.service itsec-lynis.timer)

die() { echo "install-watchdog: $*" >&2; exit 1; }
say() { echo "install-watchdog: $*"; }

PAPERCLIP="" CODE="" BASE_URL="${PCSH_BASE_URL:-}" PREFIX="" UNINSTALL=0 WATCHED_USER="paperclip" WATCHED_GIVEN=0 ADMIN_USER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --paperclip) PAPERCLIP="${2:-}"; shift 2 ;;
    --enrol) CODE="${2:-}"; shift 2 ;;
    --base-url) BASE_URL="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --watched-user) WATCHED_USER="${2:-}"; WATCHED_GIVEN=1; shift 2 ;;
    --admin-user) ADMIN_USER="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

if [ -n "$PREFIX" ]; then
  case "$PREFIX" in /*) ;; *) die "--prefix must be an absolute path" ;; esac
  PREFIX="${PREFIX%/}"
  mkdir -p "$PREFIX"
else
  [ "$(id -u)" -eq 0 ] || die "run this with sudo (as the admin account, not Paperclip's account)"
fi
R="$PREFIX"
OPT="$R/opt/itsec" ETC="$R/etc/itsec" UNITDIR="$R/etc/systemd/system" STATE="$R/var/lib/itsec"

# Privileged system changes: real commands, or "would run" lines in a --prefix test install.
run() { if [ -n "$PREFIX" ]; then echo "would run: $*"; else "$@"; fi; }

# The ACL entries go through the helper that walks each path without following a symlink (see host/itsec/itsec/acl.py).
# Its exit codes, the same for grants and removals: 0 done (a path that is gone counts); 2 refused (the path is unsafe or cannot be
# looked at, e.g. a symlink, a foreign owner, a mount the watched account made): reported, the run goes on with the next path;
# 1 setfacl failed or an unexpected error: a grant stops the install (re-running is safe), a removal is reported and goes on.
# -B: root does not write bytecode into /opt/itsec.
acl_helper() { local uid="$1"; shift; run python3 -I -B "$OPT/bin/itsec-acl" --uid "$uid" "$@"; }

need() { for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "missing command: $c"; done; }

# -------------------------------------------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
  if [ -f "$ETC/config.json" ] && [ -f "$ETC/watchdog-key.pem" ] && [ -x "$OPT/bin/itsec-plugin" ]; then
    if python3 -I "$OPT/bin/itsec-plugin" --config "$ETC/config.json" --key "$ETC/watchdog-key.pem" unenrol >/dev/null 2>&1; then
      say "the plugin was told that the watchdog is removed"
    else
      say "could not reach the plugin (the Watchdog row will turn red after 30 minutes without heartbeat)"
    fi
  fi
  run systemctl disable --now "${TIMERS[@]}" || true
  # The read access this installer granted (while the user itsec still exists, so the name resolves). The list is written
  # before the grants, so it may name paths that were never applied: those, and paths that are gone, are skipped. An entry
  # that cannot be removed (the helper refuses the path or fails, or the account is gone) is printed and kept in $LEFT: /etc/itsec
  # is deleted below, so without that file nobody could trace the ACL that is left. /root is root-only, outside every directory
  # this script deletes, and the first place an admin looks for what a root-run script left behind.
  LEFT="$R/root/itsec-acl-paths.left"
  if [ -f "$ETC/acl-paths" ]; then
    ACL_UID="" LEFT_ENTRIES=()
    if [ -n "$PREFIX" ]; then ACL_UID="$(id -u)"
    elif [ -f "$ETC/config.json" ]; then
      ACL_UID="$(id -u -- "$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("watched_user",""))' "$ETC/config.json")" 2>/dev/null || true)"
    fi
    if [ -z "$ACL_UID" ] || [ ! -f "$OPT/bin/itsec-acl" ]; then
      say "cannot remove the read access of itsec (the watched account or $OPT/bin/itsec-acl is gone)"
      while IFS=$'\t' read -r kind p; do [ -z "$p" ] || LEFT_ENTRIES+=("$kind"$'\t'"$p"); done < "$ETC/acl-paths"
    else
      n=0
      while IFS=$'\t' read -r kind p; do
        if [ -z "$p" ] || [ ! -e "$p" ] || [ -L "$p" ]; then continue; fi
        if acl_helper "$ACL_UID" remove "$kind" "$p"; then n=$((n + 1))
        else say "could not remove the read access of itsec from $p (see above)"; LEFT_ENTRIES+=("$kind"$'\t'"$p"); fi
      done < "$ETC/acl-paths"
      say "removed the read access of itsec from $n watched path(s)"
    fi
    if [ "${#LEFT_ENTRIES[@]}" -gt 0 ]; then
      mkdir -p -m 0700 "$R/root"
      { if [ -f "$LEFT" ]; then cat "$LEFT"; fi; printf '%s\n' "${LEFT_ENTRIES[@]}"; } | (umask 077; sort -u > "$LEFT.new")
      mv -f "$LEFT.new" "$LEFT"
      ITSEC_UID="$(id -u itsec 2>/dev/null || true)"
      say "NOT removed: itsec may still have read access on ${#LEFT_ENTRIES[@]} path(s) (kind, path; R = a whole tree):"
      printf '  %s\n' "${LEFT_ENTRIES[@]}"
      say "this list is saved in $LEFT (root only; it is not deleted with $ETC). Check a path with getfacl -p PATH; take the entry away with: setfacl -x u:${ITSEC_UID:-<uid of the deleted itsec user>} PATH (add -R for kind R)"
    fi
  fi
  for u in "${UNITS[@]}" itsec-lynis-root.service; do rm -f "$UNITDIR/$u"; done
  run systemctl daemon-reload || true
  created_group=0
  [ -f "$ETC/installed-by" ] && grep -qx 'created_group=1' "$ETC/installed-by" && created_group=1
  if [ -n "$PREFIX" ] || getent passwd itsec >/dev/null; then run userdel itsec || true; fi
  if [ "$created_group" -eq 1 ]; then run groupdel vaultaudit || true; fi
  rm -rf "$OPT" "$ETC" "$STATE"
  say "removed: timers, units, user itsec, /opt/itsec, /etc/itsec, /var/lib/itsec"
  exit 0
fi

# -------------------------------------------------------------------------------------------------- install
case "$BUNDLE_SHA256" in [0-9a-f]*) [ "${#BUNDLE_SHA256}" -eq 64 ] || die "corrupt pinned fingerprint" ;; *) die "this is not a release build of the installer (no pinned bundle fingerprint); download it from the release page" ;; esac
need curl sha256sum tar python3 openssl install realpath
[ -n "$PREFIX" ] || need setfacl getent     # setfacl: package "acl"
BASE_URL="${BASE_URL:-$DEFAULT_BASE_URL}"
case "$BASE_URL" in
  https://*) CURL_PROTO="=https" ;;
  file://*) [ -n "$PREFIX" ] || die "file:// downloads are only for --prefix test installs"; CURL_PROTO="=file" ;;
  *) die "the download URL must be https://" ;;
esac
case "$BASE_URL" in */) ;; *) BASE_URL="$BASE_URL/" ;; esac

if [ -n "$PAPERCLIP" ]; then
  [[ "$PAPERCLIP" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] || die "--paperclip must be http(s)://host or http(s)://host:port"
  PAPERCLIP="${PAPERCLIP%/}"
fi
if [ -n "$CODE" ]; then
  [[ "$CODE" =~ ^[A-Za-z0-9-]{8,40}$ ]] || die "the enrolment code is malformed (copy the whole line from the Hardening page again)"
fi
USER_RE='^[a-z_][a-z0-9_-]{0,31}$'
[[ "$WATCHED_USER" =~ $USER_RE ]] || die "--watched-user is not a valid user name"
[ -z "$ADMIN_USER" ] || [[ "$ADMIN_USER" =~ $USER_RE ]] || die "--admin-user is not a valid user name"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
say "downloading ${BASE_URL}${BUNDLE}"
curl -fsSL --proto "$CURL_PROTO" "${BASE_URL}${BUNDLE}" -o "$TMP/bundle.tar.gz" || die "download failed"
echo "${BUNDLE_SHA256}  $TMP/bundle.tar.gz" | sha256sum -c --status - \
  || die "the bundle's fingerprint does not match the one pinned in this installer; nothing was installed"
tar -tzf "$TMP/bundle.tar.gz" > "$TMP/list" || die "the bundle is not a readable archive"
if grep -Eq '(^/|(^|/)\.\.(/|$))' "$TMP/list"; then die "the bundle contains unsafe paths"; fi
mkdir "$TMP/x"
tar -xzf "$TMP/bundle.tar.gz" -C "$TMP/x" --no-same-owner --no-same-permissions
SRC="$TMP/x/paperclip-watchdog"
for f in bin/itsec-collect bin/itsec-plugin bin/itsec-acl itsec/acl.py itsec/notify.py systemd/itsec-collect.service fail2ban/jail.local config.example.json; do
  [ -e "$SRC/$f" ] || die "the bundle is incomplete ($f missing)"
done

# Existing config: keep it (the plugin URL is updated when --paperclip is given).
if [ ! -f "$ETC/config.json" ] && [ -z "$PAPERCLIP" ]; then die "first install: --paperclip URL is required"; fi
if [ -z "$PAPERCLIP" ]; then
  PAPERCLIP="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("paperclip",{}).get("base_url",""))' "$ETC/config.json")"
fi

# The account to watch: an existing config decides (the options only apply to a new one); its home is where the read access goes.
if [ -f "$ETC/config.json" ]; then
  CONFIG_WATCHED="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("watched_user",""))' "$ETC/config.json")"
  [[ "$CONFIG_WATCHED" =~ $USER_RE ]] || die "watched_user in $ETC/config.json is not a valid user name"
  [ "$WATCHED_GIVEN" -eq 0 ] || [ "$CONFIG_WATCHED" = "$WATCHED_USER" ] || say "note: $ETC/config.json already watches $CONFIG_WATCHED; --watched-user $WATCHED_USER is ignored (edit the config to change it)"
  WATCHED_USER="$CONFIG_WATCHED"
fi
if [ -n "$PREFIX" ]; then WATCHED_HOME="/home/$WATCHED_USER"
else
  WATCHED_HOME="$(getent passwd "$WATCHED_USER" | cut -d: -f6)"
  [ -n "$WATCHED_HOME" ] || die "the watched user \"$WATCHED_USER\" does not exist on this host (--watched-user must name the account Paperclip runs as)"
fi

# The collector may only reach Paperclip (IPAddressAllow in the unit): resolve the host once, here.
HOST="${PAPERCLIP#*://}"; HOST="${HOST%%:*}"; HOST="${HOST%%/*}"
if [[ "$HOST" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then IP="$HOST"
elif [ "$HOST" = localhost ]; then IP="127.0.0.1"
else IP="$(getent ahostsv4 "$HOST" 2>/dev/null | awk 'NR==1{print $1}')"; [ -n "$IP" ] || die "cannot resolve $HOST"
fi

# 1. user and groups
created_group=0
if [ -n "$PREFIX" ]; then
  run groupadd --system vaultaudit
  run useradd --system --home-dir /var/lib/itsec --no-create-home --shell /usr/sbin/nologin itsec
else
  if ! getent group vaultaudit >/dev/null; then groupadd --system vaultaudit; created_group=1; fi
  getent passwd itsec >/dev/null || useradd --system --home-dir /var/lib/itsec --no-create-home --shell /usr/sbin/nologin itsec
fi
run usermod -aG adm,systemd-journal,vaultaudit itsec

# 2. code (root-owned, so the itsec user cannot rewrite its own detector)
install -d -m 0755 "$OPT" "$ETC" "$UNITDIR"
rm -rf "$OPT/bin" "$OPT/itsec" "$OPT/fail2ban"
cp -r "$SRC/bin" "$SRC/itsec" "$SRC/fail2ban" "$OPT/"
cp "$SRC/INSTALL.md" "$OPT/INSTALL.md" 2>/dev/null || true
find "$OPT" -name __pycache__ -prune -exec rm -rf {} +
chmod -R go-w "$OPT"
chmod 0755 "$OPT"/bin/*
run chown -R root:root "$OPT"
echo "$VERSION" > "$OPT/VERSION"

# 3. key and install id (kept on re-runs)
if [ ! -s "$ETC/watchdog-key.pem" ]; then
  (umask 077; openssl genpkey -algorithm ed25519 -out "$ETC/watchdog-key.pem" 2>/dev/null) || die "openssl cannot create an Ed25519 key (OpenSSL 1.1.1 or newer is needed)"
fi
chmod 0600 "$ETC/watchdog-key.pem"
run chown root:root "$ETC/watchdog-key.pem"
if [ ! -s "$ETC/install-id" ]; then
  echo "inst-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')" > "$ETC/install-id"
fi
INSTALL_ID="$(tr -cd 'A-Za-z0-9-' < "$ETC/install-id")"
[ "${#INSTALL_ID}" -ge 8 ] || die "corrupt $ETC/install-id"

# 4. config (no secrets in it): notifier "plugin" posting to the plugin webhook
WEBHOOK="${PAPERCLIP}/api/plugins/${PLUGIN_KEY}/webhooks/watchdog"
python3 -I - "$SRC/config.example.json" "$ETC/config.json" "$WEBHOOK" "$INSTALL_ID" "$VERSION" "$PAPERCLIP" "$WATCHED_USER" "$(command -v openssl)" \
  "$ADMIN_USER" "${SUDO_USER:-}" "$WATCHED_HOME" "$R/var/log/vault" <<'PY'
import json, os, pwd, re, sys
example, target, webhook, install_id, version, paperclip, watched, openssl, admin_opt, sudo_user, home, vault_dir = sys.argv[1:13]


def note(msg):
    print("install-watchdog: " + msg)


def rehome(v):                       # the example watches /home/paperclip; the account to watch may live elsewhere
    if isinstance(v, str) and (v == "/home/paperclip" or v.startswith("/home/paperclip/")):
        return home + v[len("/home/paperclip"):]
    if isinstance(v, list):
        return [rehome(x) for x in v]
    if isinstance(v, dict):
        return {k: rehome(x) for k, x in v.items()}
    return v


if os.path.exists(target):
    with open(target) as f:
        cfg = json.load(f)
    note("kept the existing config (watched_user %s, admin_user %s); edit %s to change them" % (cfg.get("watched_user"), cfg.get("admin_user"), "/etc/itsec/config.json"))
else:
    with open(example) as f:
        cfg = json.load(f)
    cfg["watched_user"] = watched
    try:
        cfg["watched_uid"] = str(pwd.getpwnam(watched).pw_uid)
    except KeyError:
        pass
    cfg["watch"] = rehome(cfg["watch"])
    cfg["paperclip"]["company_id"] = cfg["paperclip"]["assignee_user_id"] = ""
    ok = lambda u: re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", u or "") is not None
    if admin_opt:
        cfg["admin_user"] = admin_opt
        note("admin account: %s (--admin-user)" % admin_opt)
    elif ok(sudo_user) and sudo_user not in ("root", watched):
        cfg["admin_user"] = sudo_user
        note("admin account: %s (the account that ran sudo)" % sudo_user)
    else:
        note('admin account unknown (no --admin-user, and sudo was not run from a named admin account): admin_user stays "%s"; set it in /etc/itsec/config.json if your admin account is named differently' % cfg.get("admin_user"))
    if not os.path.isdir(vault_dir):  # no vault on this host: an empty path switches that check off
        cfg["vault_audit_log"] = ""
cfg["notifier"] = "plugin"
cfg.setdefault("paperclip", {})["base_url"] = paperclip
cfg["plugin"] = dict(cfg.get("plugin", {}), url=webhook, install_id=install_id,
                     key_file="${CREDENTIALS_DIRECTORY}/watchdog-key", openssl=openssl, version=version)
tmp = target + ".new"
with open(tmp, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
os.chmod(tmp, 0o644)
os.replace(tmp, target)
PY
run chown root:root "$ETC/config.json"

# 5. units: the key as a credential; credentials whose file does not exist here are left out (a missing
#    LoadCredential source would stop the unit); the collector may reach only Paperclip.
for u in "${UNITS[@]}"; do
  python3 -I - "$SRC/systemd/$u" "$UNITDIR/$u" "$IP" "$ETC" <<'PY'
import os, sys
src, dst, ip, etc = sys.argv[1:5]
out = []
for line in open(src).read().splitlines():
    if line.startswith("LoadCredential="):
        name, path = line[len("LoadCredential="):].split(":", 1)
        if not os.path.exists(os.path.join(etc, os.path.basename(path))):
            continue
    out.append(line.replace("PAPERCLIP_HOST_IP", ip))
    if line.startswith("Environment=ITSEC_CONFIG=") and src.endswith(".service"):
        out.append("LoadCredential=watchdog-key:/etc/itsec/watchdog-key.pem")
tmp = dst + ".new"
with open(tmp, "w") as f:
    f.write("\n".join(out) + "\n")
os.chmod(tmp, 0o644)
os.replace(tmp, dst)
PY
done
if [ "$created_group" -eq 1 ] || { [ -f "$ETC/installed-by" ] && grep -qx 'created_group=1' "$ETC/installed-by"; }; then
  echo "created_group=1" > "$ETC/installed-by"
else
  echo "created_group=0" > "$ETC/installed-by"
fi

# 6. enrol with the plugin (the code goes to the helper on stdin only)
if [ -n "$CODE" ]; then
  if printf '%s\n' "$CODE" | python3 -I "$OPT/bin/itsec-plugin" --config "$ETC/config.json" --key "$ETC/watchdog-key.pem" enrol >/dev/null; then
    say "enrolled with the Security hardening plugin at $PAPERCLIP"
  else
    die "enrolment failed (code expired or already used, or Paperclip unreachable). Open the Watchdog switch again for a new line; re-running is safe."
  fi
fi
CODE=""

# 7. read access to the files the watchdog watches in the watched user's home, and the patch manifest.
#    The home is 0750, so itsec gets traversal (x) on the directories above each watched path and read (r) on the paths
#    themselves; no key, credential or conversation is named. The home belongs to the account the agents run as, which can
#    swap a directory for a symlink at any moment: a path that is, or sits behind, a symlink is skipped here, and
#    itsec-acl re-checks every component (type and owner) on the descriptor it applies the entry to. Every path to grant
#    is recorded in $ETC/acl-paths (kind <tab> path; R = recursive) BEFORE the first grant, so a failure half way never
#    leaves an unrecorded grant; --uninstall takes exactly those entries away.
HP="$(realpath -m -- "$R$WATCHED_HOME")"
TREE_LINK="$HP/.paperclip/cli/current"
GRANTS="$TMP/grants"; : > "$GRANTS"
acl_chain() {   # x on every directory from the home down to the parent of $1
  local d; d="$(dirname -- "$1")"
  while [ "$d" != "$HP" ] && [ "$d" != / ]; do printf 'x\t%s\n' "$d" >> "$GRANTS"; d="$(dirname -- "$d")"; done
  printf 'x\t%s\n' "$HP" >> "$GRANTS"
}
acl_want() {    # kind (r = file, R = directory tree), path
  local kind="$1" p="$2"
  [ -e "$p" ] || [ -L "$p" ] || return 0
  if [ "$(realpath -m -- "$p")" != "$p" ]; then say "no read access for $p (it is, or sits behind, a symlink)"; return 0; fi
  acl_chain "$p"
  printf '%s\t%s\n' "$kind" "$p" >> "$GRANTS"
}
for f in .claude/settings.json .claude/settings.local.json .claude/CLAUDE.md .bashrc .profile .bash_logout \
         .ssh/authorized_keys .ssh/authorized_keys2 .ssh/rc .ssh/config; do acl_want r "$HP/$f"; done
for d in .config/systemd/user .config/environment.d .local/bin .claude/skills .claude/plugins .claude/agents .claude/commands .claude/hooks; do
  acl_want R "$HP/$d"
done
# Each agent's own Claude settings. The agents' directories are made by the account the agents run as: find looks at no more than
# ENTRIES_MAX directory entries in all (it is stopped when it has shown that many, matches or not), at most AGENTS_MAX files
# are taken, and more than either is refused as a whole, never half granted. Only .../companies/*/agents/*/.claude is entered.
AGENTS_MAX=500
ENTRIES_MAX=20000
COMPANIES="$HP/.paperclip/instances/default/companies"
CRE="$(printf '%s' "$COMPANIES" | sed 's/[][\.*^$+?(){}|]/\\&/g')"
AGENT_FILES=(); entries=0; AGENTS_OVER=""
if [ -d "$COMPANIES" ]; then
  while IFS= read -r -d '' rec; do
    entries=$((entries + 1))
    [ "${rec:0:1}" != f ] || AGENT_FILES+=("${rec:1}")
    if [ "$entries" -gt "$ENTRIES_MAX" ]; then AGENTS_OVER="$ENTRIES_MAX directory entries"; break; fi
    if [ "${#AGENT_FILES[@]}" -gt "$AGENTS_MAX" ]; then AGENTS_OVER="$AGENTS_MAX of them"; break; fi
  done < <(find "$COMPANIES" -mindepth 1 -maxdepth 5 -regextype posix-extended \
             \( -type d \( \( -regex "$CRE/[^/]+/[^/]+" ! -regex "$CRE/[^/]+/agents" \) -o \
                 \( -regex "$CRE/[^/]+/agents/[^/]+/[^/]+" ! -regex "$CRE/[^/]+/agents/[^/]+/\\.claude" \) \) -prune -printf 'x\0' \) -o \
             \( -regex "$CRE/[^/]+/agents/[^/]+/\\.claude/settings[^/]*\\.json" -printf 'f%p\0' \) -o -printf 'x\0' 2>/dev/null)
fi
if [ -n "$AGENTS_OVER" ]; then
  say "no read access for the agents' Claude settings: more than $AGENTS_OVER under $COMPANIES (refused)"
else
  for f in "${AGENT_FILES[@]}"; do acl_want r "$f"; done
fi
# The patched Paperclip files: the manifest generator lists them (one table for the manifest and the access). A link that
# cannot be resolved (a symlink loop) leaves TREE empty: the tree steps are skipped, everything else still installs.
TREE="$(realpath -m -- "$TREE_LINK" 2>/dev/null || true)"
case "$TREE" in
  "$HP/.paperclip/cli/installs/npm/"*)
    while IFS= read -r f; do
      rf="$(realpath -m -- "$f" 2>/dev/null || true)"
      case "$rf" in "$TREE"/*) acl_want r "$rf" ;; *) say "no read access for $f (it resolves outside the Paperclip install)" ;; esac
    done < <(python3 -I -B "$OPT/bin/itsec-make-manifest" --tree "$TREE_LINK" --list-paths) ;;
  "") say "cannot resolve $TREE_LINK (a symlink loop?): the patched files are not watched until it is fixed (run this installer again)" ;;
  *) say "no Paperclip install found at $TREE_LINK: the patched files are not watched until it exists (run this installer again)" ;;
esac
# Record first (and keep earlier paths too, e.g. an older Paperclip version's directory), then grant: --uninstall finds every entry
# even if this run stops half way.
sort -u "$GRANTS" > "$GRANTS.sorted"
if [ -f "$ETC/acl-paths" ]; then sort -u "$GRANTS.sorted" "$ETC/acl-paths" > "$ETC/acl-paths.new"; else cp "$GRANTS.sorted" "$ETC/acl-paths.new"; fi
mv -f "$ETC/acl-paths.new" "$ETC/acl-paths"
if [ -n "$PREFIX" ]; then ACL_UID="$(id -u)"; else ACL_UID="$(id -u -- "$WATCHED_USER")"; fi
# Directories first, then files and trees (a later entry for the same path replaces an earlier one).
n=0
for kind in x r R; do
  while IFS=$'\t' read -r k p; do
    [ "$k" = "$kind" ] || continue
    rc=0; acl_helper "$ACL_UID" grant "$kind" "$p" || rc=$?
    case "$rc" in
      0) n=$((n + 1)) ;;
      2) say "no read access for $p (refused, see above)" ;;
      *) die "could not give itsec read access to $p (the file system needs ACL support); re-running is safe; every path to grant is already listed in $ETC/acl-paths, so --uninstall takes back what was granted" ;;
    esac
  done < "$GRANTS.sorted"
done
say "read access for itsec granted on $n path(s) (list: $ETC/acl-paths)"
if [ -z "$TREE" ]; then
  say "the patch manifest was NOT written: $TREE_LINK cannot be resolved; until it is fixed and this installer is run again the watchdog reports watch-degraded (an older manifest stays in place)"
elif python3 -I -B "$OPT/bin/itsec-make-manifest" --uid "$ACL_UID" --tree "$TREE_LINK" --out "$ETC/patch-manifest.json" > "$TMP/manifest.out" 2> "$TMP/manifest.err"; then
  say "$(tail -n1 "$TMP/manifest.out")"
else
  say "the patch manifest was NOT written: $(tail -n1 "$TMP/manifest.err")"
  say "turn the protections on in the Hardening page, restart Paperclip, then run this installer again; until then the watchdog reports watch-degraded (an older manifest stays in place)"
fi

# 8. baseline run (also the first heartbeat), then the timers
run systemctl daemon-reload
run systemctl start itsec-collect.service || say "the first collector run failed; see journalctl -u itsec-collect.service"
ENABLE=(itsec-collect.timer itsec-report.timer)
if command -v lynis >/dev/null 2>&1; then
  ENABLE+=(itsec-lynis.timer)
else
  say "lynis is not installed, so the weekly audit timer stays off; after 'apt-get install lynis' run: sudo systemctl enable --now itsec-lynis.timer"
fi
run systemctl enable --now "${ENABLE[@]}"
say "installed watchdog ${VERSION} (install id ${INSTALL_ID})."
cat <<EOF
Not done by this installer (optional): fail2ban, see /opt/itsec/INSTALL.md section 6.
Check what the watchdog still cannot read:
  sudo -u itsec env ITSEC_CONFIG=/etc/itsec/config.json /opt/itsec/bin/itsec-collect --dry-run
After a Paperclip update, paste the install line from the Hardening page again: it refreshes the read access and the patch manifest.
EOF
