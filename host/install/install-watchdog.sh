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
#   --watched-user U  the account Paperclip runs as (default: paperclip); written into a NEW config only
#   --prefix DIR      install into a fake root for tests: no useradd/systemctl/chown, prints "would run: ..." instead
#   --uninstall       remove everything this script installed (tells the plugin first, best effort)
#
# What it does (see host/itsec/INSTALL.md for the manual steps it automates):
#   1. downloads the bundle from the official release and checks it against the sha256 pinned below (written by
#      scripts/release.sh); a mismatch stops before anything is installed;
#   2. creates the system user `itsec` (no shell, no sudo; groups adm, systemd-journal, vaultaudit) and installs the
#      code root-owned under /opt/itsec, the config under /etc/itsec, the units under /etc/systemd/system;
#   3. generates the watchdog's Ed25519 key (/etc/itsec/watchdog-key.pem, root 0600, handed to the units with
#      LoadCredential) and enrols its public key with the Sandbox hardening plugin using the one-time code. No
#      Paperclip board or agent key is created or stored on this host;
#   4. runs the first collector pass (baseline; it also sends the first heartbeat) and enables the timers.
# Not automated (printed at the end): the read ACLs on the watched user's files (INSTALL.md step 4), the patch
# manifest (step 5b), fail2ban (step 6). Idempotent: running it again updates the code and units and keeps the key,
# the install id and the config.
set -euo pipefail
umask 022

VERSION="__VERSION__"
BUNDLE_SHA256="__BUNDLE_SHA256__"
DEFAULT_BASE_URL="__BASE_URL__"
PLUGIN_KEY="paperclip-sandbox-hardening"
BUNDLE="paperclip-watchdog-${VERSION}.tar.gz"
TIMERS=(itsec-collect.timer itsec-report.timer itsec-lynis.timer)
UNITS=(itsec-collect.service itsec-collect.timer itsec-report.service itsec-report.timer itsec-lynis.service itsec-lynis.timer)

die() { echo "install-watchdog: $*" >&2; exit 1; }
say() { echo "install-watchdog: $*"; }

PAPERCLIP="" CODE="" BASE_URL="${PCSH_BASE_URL:-}" PREFIX="" UNINSTALL=0 WATCHED_USER="paperclip"
while [ $# -gt 0 ]; do
  case "$1" in
    --paperclip) PAPERCLIP="${2:-}"; shift 2 ;;
    --enrol) CODE="${2:-}"; shift 2 ;;
    --base-url) BASE_URL="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --watched-user) WATCHED_USER="${2:-}"; shift 2 ;;
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
need curl sha256sum tar python3 openssl install
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
[[ "$WATCHED_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "--watched-user is not a valid user name"

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
for f in bin/itsec-collect bin/itsec-plugin itsec/notify.py systemd/itsec-collect.service config.example.json; do
  [ -e "$SRC/$f" ] || die "the bundle is incomplete ($f missing)"
done

# Existing config: keep it (the plugin URL is updated when --paperclip is given).
if [ ! -f "$ETC/config.json" ] && [ -z "$PAPERCLIP" ]; then die "first install: --paperclip URL is required"; fi
if [ -z "$PAPERCLIP" ]; then
  PAPERCLIP="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("paperclip",{}).get("base_url",""))' "$ETC/config.json")"
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
rm -rf "$OPT/bin" "$OPT/itsec"
cp -r "$SRC/bin" "$SRC/itsec" "$OPT/"
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
python3 -I - "$SRC/config.example.json" "$ETC/config.json" "$WEBHOOK" "$INSTALL_ID" "$VERSION" "$PAPERCLIP" "$WATCHED_USER" "$(command -v openssl)" <<'PY'
import json, os, pwd, sys
example, target, webhook, install_id, version, paperclip, watched, openssl = sys.argv[1:9]
if os.path.exists(target):
    with open(target) as f:
        cfg = json.load(f)
else:
    with open(example) as f:
        cfg = json.load(f)
    cfg["watched_user"] = watched
    try:
        cfg["watched_uid"] = str(pwd.getpwnam(watched).pw_uid)
    except KeyError:
        pass
    cfg["paperclip"]["company_id"] = cfg["paperclip"]["assignee_user_id"] = ""
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
    say "enrolled with the Sandbox hardening plugin at $PAPERCLIP"
  else
    die "enrolment failed (code expired or already used, or Paperclip unreachable). Open the Watchdog switch again for a new line; re-running is safe."
  fi
fi
CODE=""

# 7. baseline run (also the first heartbeat), then the timers
run systemctl daemon-reload
run systemctl start itsec-collect.service || say "the first collector run failed; see journalctl -u itsec-collect.service"
run systemctl enable --now "${TIMERS[@]}"
say "installed watchdog ${VERSION} (install id ${INSTALL_ID})."
cat <<EOF
Next steps (manual, see /opt/itsec/INSTALL.md):
  - read ACLs for the itsec user on the watched files in ${WATCHED_USER}'s home (INSTALL.md step 4)
  - the patch manifest: itsec-make-manifest (INSTALL.md step 5b)
  - fail2ban (INSTALL.md step 6)
EOF
