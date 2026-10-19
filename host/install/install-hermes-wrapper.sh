#!/usr/bin/env bash
# install-hermes-wrapper.sh: one-line installer for the Hermes sandbox wrapper (host/sandbox/hermes-sandbox), run by
# an admin with sudo. Only needed when Paperclip runs hermes_local agents.
#
#   sudo bash install-hermes-wrapper.sh [--path /usr/local/bin/hermes-sandbox]     install or update
#   sudo bash install-hermes-wrapper.sh --uninstall [--path ...]                     remove
#
# Options:
#   --path FILE       where the wrapper goes (default /usr/local/bin/hermes-sandbox; must match the plugin's
#                     "Hermes wrapper path" setting). Its directory must be root-owned and not writable by others.
#   --base-url URL    download location (default: the GitHub release of this version; also $PCSH_BASE_URL). Only
#                     https:// (file:// only together with --prefix, for tests).
#   --prefix DIR      install into a fake root for tests (no chown; prints "would run: ..." instead)
#   --uninstall       remove the wrapper
# The wrapper is checked against the sha256 pinned below (written by scripts/release.sh) and installed root:root 0755.
# No enrolment: the plugin's "Hermes agents boxed" row turns green by itself when it finds the file root-owned, not
# writable by others and matching the released fingerprint. Idempotent.
set -euo pipefail
umask 022

VERSION="__VERSION__"
WRAPPER_SHA256="__WRAPPER_SHA256__"
DEFAULT_BASE_URL="__BASE_URL__"
DEST="/usr/local/bin/hermes-sandbox"

die() { echo "install-hermes-wrapper: $*" >&2; exit 1; }
say() { echo "install-hermes-wrapper: $*"; }

BASE_URL="${PCSH_BASE_URL:-}" PREFIX="" UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --path) DEST="${2:-}"; shift 2 ;;
    --base-url) BASE_URL="${2:-}"; shift 2 ;;
    --prefix) PREFIX="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done
[[ "$DEST" =~ ^/[A-Za-z0-9._/-]+$ ]] && [[ ! "$DEST" =~ (^|/)\.\.(/|$) ]] && [[ "$DEST" != */ ]] || die "--path must be an absolute file path"
if [ -n "$PREFIX" ]; then
  case "$PREFIX" in /*) ;; *) die "--prefix must be an absolute path" ;; esac
  PREFIX="${PREFIX%/}"
  mkdir -p "$PREFIX"
else
  [ "$(id -u)" -eq 0 ] || die "run this with sudo (as the admin account, not Paperclip's account)"
fi
run() { if [ -n "$PREFIX" ]; then echo "would run: $*"; else "$@"; fi; }
TARGET="$PREFIX$DEST"

if [ "$UNINSTALL" -eq 1 ]; then
  rm -f "$TARGET"
  say "removed $DEST (agents whose command is the wrapper will fail to start until you change them)"
  exit 0
fi

case "$WRAPPER_SHA256" in [0-9a-f]*) [ "${#WRAPPER_SHA256}" -eq 64 ] || die "corrupt pinned fingerprint" ;; *) die "this is not a release build of the installer (no pinned wrapper fingerprint); download it from the release page" ;; esac
for c in curl sha256sum install; do command -v "$c" >/dev/null 2>&1 || die "missing command: $c"; done
BASE_URL="${BASE_URL:-$DEFAULT_BASE_URL}"
case "$BASE_URL" in
  https://*) CURL_PROTO="=https" ;;
  file://*) [ -n "$PREFIX" ] || die "file:// downloads are only for --prefix test installs"; CURL_PROTO="=file" ;;
  *) die "the download URL must be https://" ;;
esac
case "$BASE_URL" in */) ;; *) BASE_URL="$BASE_URL/" ;; esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
say "downloading ${BASE_URL}hermes-sandbox"
curl -fsSL --proto "$CURL_PROTO" "${BASE_URL}hermes-sandbox" -o "$TMP/hermes-sandbox" || die "download failed"
echo "${WRAPPER_SHA256}  $TMP/hermes-sandbox" | sha256sum -c --status - \
  || die "the wrapper's fingerprint does not match the one pinned in this installer; nothing was installed"

DIR="$(dirname "$TARGET")"
install -d -m 0755 "$DIR"
if [ -z "$PREFIX" ]; then
  # The directory must not let anyone else swap the wrapper.
  [ "$(stat -c %u "$DIR")" = 0 ] || die "$DIR is not owned by root"
  case "$(stat -c %A "$DIR")" in ?????w????|????????w?) die "$DIR is writable by group or others" ;; esac
fi
install -m 0755 "$TMP/hermes-sandbox" "$TARGET.new"
run chown root:root "$TARGET.new"
mv -f "$TARGET.new" "$TARGET"
[ -x /usr/local/bin/node ] || say "note: the wrapper runs with /usr/local/bin/node, which is not installed (or not executable) here"
say "installed $DEST (release ${VERSION}); set it as the \"Hermes wrapper path\" on the Hardening page if it differs from the default"
