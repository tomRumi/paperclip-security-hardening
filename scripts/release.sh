#!/usr/bin/env bash
# release.sh: build the root-side release files (publishes nothing).
#
#   scripts/release.sh --version 1.0.0 --org <github org> [--base-url URL] [--out DIR] [--pins-file FILE | --no-pins]
#
# Writes into --out (default ./dist):
#   paperclip-watchdog-<version>.tar.gz   the watchdog bundle (host/itsec without tests and caches), reproducible:
#                                         sorted, mtime 0, owner 0, gzip -n
#   hermes-sandbox                        the Hermes wrapper (host/sandbox/hermes-sandbox)
#   install-watchdog.sh                   host/install/install-watchdog.sh with the version, the download URL and
#                                         the bundle's sha256 pinned in it
#   install-hermes-wrapper.sh             the same with the wrapper's sha256
#   SHA256SUMS                            all of the above
# and the release pins the plugin needs for its one-line commands (version, download URL, both installers' sha256,
# the wrapper's sha256) into --pins-file (default plugin/src/release-pins.json; --no-pins leaves it alone).
# Prints the installers' own sha256 for the release notes. The download URL defaults to
#   https://github.com/<org>/paperclip-sandbox-hardening/releases/download/v<version>/
set -euo pipefail
umask 022

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="" ORG="" BASE_URL="" OUT="$HERE/dist" PINS="$HERE/plugin/src/release-pins.json" WRITE_PINS=1
die() { echo "release: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --org) ORG="${2:-}"; shift 2 ;;
    --base-url) BASE_URL="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --pins-file) PINS="${2:-}"; shift 2 ;;
    --no-pins) WRITE_PINS=0; shift ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "--version X.Y.Z is required"
if [ -z "$BASE_URL" ]; then
  [[ "$ORG" =~ ^[A-Za-z0-9-]{1,39}$ ]] || die "--org (GitHub organisation) or --base-url is required"
  BASE_URL="https://github.com/${ORG}/paperclip-sandbox-hardening/releases/download/v${VERSION}/"
fi
case "$BASE_URL" in */) ;; *) BASE_URL="$BASE_URL/" ;; esac
[[ "$BASE_URL" =~ ^(https|file)://[A-Za-z0-9._~/:-]*$ ]] || die "--base-url must be an https:// URL (file:// for tests)"
for c in tar gzip sha256sum python3; do command -v "$c" >/dev/null || die "missing command: $c"; done

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# --- the watchdog bundle
B="$STAGE/paperclip-watchdog"
mkdir -p "$B"
cp -r "$HERE/host/itsec/bin" "$HERE/host/itsec/itsec" "$HERE/host/itsec/systemd" "$HERE/host/itsec/fail2ban" "$B/"
cp "$HERE/host/itsec/config.example.json" "$HERE/host/itsec/INSTALL.md" "$HERE/host/itsec/README.md" "$B/"
find "$B" \( -name __pycache__ -o -name '*.pyc' \) -prune -exec rm -rf {} +
echo "$VERSION" > "$B/VERSION"
chmod -R u=rwX,go=rX "$B"
chmod 0755 "$B"/bin/*
BUNDLE="paperclip-watchdog-${VERSION}.tar.gz"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -C "$STAGE" -cf - paperclip-watchdog | gzip -n -9 > "$OUT/$BUNDLE"
BUNDLE_SHA="$(sha256sum "$OUT/$BUNDLE" | cut -d' ' -f1)"

# --- the Hermes wrapper
install -m 0755 "$HERE/host/sandbox/hermes-sandbox" "$OUT/hermes-sandbox"
WRAPPER_SHA="$(sha256sum "$OUT/hermes-sandbox" | cut -d' ' -f1)"

# --- the installers with their pins
pin() { # src dst
  sed -e "s|__VERSION__|${VERSION}|g" -e "s|__BASE_URL__|${BASE_URL}|g" -e "s|__BUNDLE_SHA256__|${BUNDLE_SHA}|g" -e "s|__WRAPPER_SHA256__|${WRAPPER_SHA}|g" "$1" > "$2"
  chmod 0755 "$2"
  if grep -q '__[A-Z0-9_]*__' "$2"; then die "unfilled placeholder in $2"; fi
  bash -n "$2" || die "syntax error in $2"
}
pin "$HERE/host/install/install-watchdog.sh" "$OUT/install-watchdog.sh"
pin "$HERE/host/install/install-hermes-wrapper.sh" "$OUT/install-hermes-wrapper.sh"
IW_SHA="$(sha256sum "$OUT/install-watchdog.sh" | cut -d' ' -f1)"
IH_SHA="$(sha256sum "$OUT/install-hermes-wrapper.sh" | cut -d' ' -f1)"
(cd "$OUT" && sha256sum "$BUNDLE" hermes-sandbox install-watchdog.sh install-hermes-wrapper.sh > SHA256SUMS)

if [ "$WRITE_PINS" -eq 1 ]; then
  python3 -I - "$PINS" "$VERSION" "$BASE_URL" "$IW_SHA" "$IH_SHA" "$WRAPPER_SHA" <<'PY'
import json, os, sys
path, version, base, iw, ih, wrap = sys.argv[1:7]
pins = {"comment": "Written by scripts/release.sh. The plugin shows the one-line install commands from these values.",
        "version": version, "baseUrl": base, "installWatchdogSha256": iw, "installHermesSha256": ih, "hermesWrapperSha256": wrap}
tmp = path + ".new"
with open(tmp, "w") as f:
    json.dump(pins, f, indent=2)
    f.write("\n")
os.replace(tmp, path)
PY
fi

cat <<EOF
release ${VERSION} built in ${OUT} (nothing published)
download URL: ${BASE_URL}
for the release notes:
  ${IW_SHA}  install-watchdog.sh
  ${IH_SHA}  install-hermes-wrapper.sh
  ${BUNDLE_SHA}  ${BUNDLE}
  ${WRAPPER_SHA}  hermes-sandbox
EOF
[ "$WRITE_PINS" -eq 1 ] && echo "release pins written to ${PINS}" || true
