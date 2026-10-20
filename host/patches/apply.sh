#!/usr/bin/env bash
# Re-apply our local Paperclip patches to the installed tree (run after every `paperclipai` update).
#   apply.sh            apply every patch that is not applied yet (idempotent; keeps <file>.orig once)
#   apply.sh --check    only report the status of each patch; changes nothing
# Tree: $PAPERCLIP_TREE, else what ~/.paperclip/cli/current resolves to. Patches are `patch -p1` against that tree.
# Version selection: patch `X.patch` may have a variant `X.<MMDD>.patch` (MMDD = 2nd field of the @paperclipai/server
# version, e.g. 1012 for 2026.1012.0); the variant wins. A 5th field lists the vkeys (comma separated, e.g. `1005`) for which
# the entry is optional: with no file for such a version it is skipped. Any other version without a file is an error, and an
# unparseable version / empty vkey is an error too (never a silent skip).
# All-or-nothing: every pending patch is first trial-applied in sequence on a scratch copy of the target files; if any
# patch (or an already-applied one that is only partly present) does not fit, NOTHING is changed.
# Exit: 0 all applied | 1 a patch does not fit (tree untouched) | 3 --check found pending patches.
# The patch list is the same as the plugin engine's (plugin/src/engine/registry.js, a test compares the two builds byte for byte);
# apply.sh is the command-line route for a tree nobody manages with the plugin. Patches that stack on one file (0003 then 0003b)
# are listed in the order they apply, and "already applied" is checked newest first. A tree patched with an OLDER patch set (for
# example 0005a of v0.1.1) is reported as partly applied: restore the `.orig` files and run again, or let the plugin rebuild it.
# Paperclip is NOT restarted here; the server and adapter-utils load the files at start, so restart after a change.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
tree=$(readlink -f "${PAPERCLIP_TREE:-$HOME/.paperclip/cli/current}")
mode=apply; [ "${1:-}" = "--check" ] && mode=check
[ -d "$tree/node_modules/@paperclipai" ] || { echo "apply.sh: no @paperclipai packages under $tree" >&2; exit 1; }

ver=$(sed -n 's/^  "version": *"\([^"]*\)".*/\1/p' "$tree/node_modules/@paperclipai/server/package.json" | head -1)
vkey=$(cut -d. -f2 <<<"$ver")
echo "tree: $tree (paperclipai $ver)"
[[ "$vkey" =~ ^[0-9]{4}$ ]] || { echo "apply.sh: cannot determine the paperclipai version (ver='$ver' vkey='$vkey'); NOTHING was changed" >&2; exit 1; }

# id | patch file | target file (relative to tree) | marker | optional-for-vkeys
patches=(
  "0001|$here/0001-sandbox-usrmerge-mounts.patch|node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js|// LOCAL-PATCH 0001"
  "0002|$here/0002-agent-self-config-change-grant.patch|node_modules/@paperclipai/server/dist/routes/agents.js|// LOCAL-PATCH 0002"
  "0003|$here/0003-spawn-time-sandbox-enforcement.patch|node_modules/@paperclipai/server/dist/services/heartbeat.js|// LOCAL-PATCH 0003"
  "0003b|$here/0003b-hermes-engine-env-redirects.patch|node_modules/@paperclipai/server/dist/services/heartbeat.js|// LOCAL-PATCH 0003b"
  "0004|$here/0004-sandbox-proxy-epipe.patch|node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js|// LOCAL-PATCH 0004"
  "0005a|$here/0005a-new-agent-safe-defaults.patch|node_modules/@paperclipai/server/dist/services/agents.js|// LOCAL-PATCH 0005a"
  "0005c|$here/0005c-no-default-task-assign.patch|node_modules/@paperclipai/server/dist/routes/agents.js|// LOCAL-PATCH 0005c"
  "0005d|$here/0005d-no-default-task-assign-import.patch|node_modules/@paperclipai/server/dist/services/company-portability.js|// LOCAL-PATCH 0005d"
  "0005e|$here/0005e-no-default-agent-grants.patch|node_modules/@paperclipai/server/dist/services/agent-permissions.js|// LOCAL-PATCH 0005e|1005"
  "0005b|$here/0005b-fail-closed-spawn.patch|node_modules/@paperclipai/server/dist/services/heartbeat.js|// LOCAL-PATCH 0005b"
  "0005f|$here/0005f-table-driven-admission.patch|node_modules/@paperclipai/server/dist/services/heartbeat.js|// LOCAL-PATCH 0005f"
  "0006a|$here/0006a-git-common-dir-spawn.patch|node_modules/@paperclipai/server/dist/services/heartbeat.js|// LOCAL-PATCH 0006"
  "0006b|$here/0006b-git-common-dir-sandbox-check.patch|node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js|// LOCAL-PATCH 0006"
  "0007|$here/0007-pipeline-structure-board-only.patch|node_modules/@paperclipai/server/dist/routes/pipelines.js|// LOCAL-PATCH 0007"
  "0008|$here/0008-adapterconfig-redacted-restore.patch|node_modules/@paperclipai/server/dist/services/agents.js|// LOCAL-PATCH 0008"
  "0009|$here/0009-agent-permissions-grant-board-only.patch|node_modules/@paperclipai/server/dist/routes/agents.js|// LOCAL-PATCH 0009"
  "0010|$here/0010-no-ceo-default-change-grants.patch|node_modules/@paperclipai/server/dist/services/built-in-agents.js|// LOCAL-PATCH 0010"
  "0011a|$here/0011a-agent-permissions-can-write-pipelines-schema.patch|node_modules/@paperclipai/shared/dist/validators/agent.js|// LOCAL-PATCH 0011"
  "0011b|$here/0011b-agent-permissions-can-write-pipelines.patch|node_modules/@paperclipai/server/dist/routes/agents.js|// LOCAL-PATCH 0011"
  "0012|$here/0012-sandbox-no-proxy-localhost.patch|node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js|// LOCAL-PATCH 0012"
  "0013a|$here/0013a-agent-assign-needs-explicit-grant.patch|node_modules/@paperclipai/server/dist/services/authorization.js|// LOCAL-PATCH 0013"
  "0013b|$here/0013b-agent-access-no-simple-default.patch|node_modules/@paperclipai/server/dist/routes/agents.js|// LOCAL-PATCH 0013"
  "0014|$here/0014-interaction-pending-addressee-wake.patch|node_modules/@paperclipai/server/dist/modules/run-dispatch/adapters/postgres.js|// LOCAL-PATCH 0014"
  "0015|$here/0015-sandbox-public-web-wildcard.patch|node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js|// LOCAL-PATCH 0015"
  "0016|$here/0016-per-agent-claude-config.patch|node_modules/@paperclipai/adapter-claude-local/dist/server/execute.js|// LOCAL-PATCH 0016"
  "0017|$here/0017-boxed-sandbox-helper.patch|node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js|// LOCAL-PATCH 0017"
  "0019|$here/0019-opencode-boxed-run.patch|node_modules/@paperclipai/adapter-opencode-local/dist/server/execute.js|// LOCAL-PATCH 0019"
  "0019b|$here/0019b-opencode-boxed-model-discovery.patch|node_modules/@paperclipai/adapter-opencode-local/dist/server/models.js|// LOCAL-PATCH 0019b"
  "0019c|$here/0019c-opencode-boxed-runtime-config.patch|node_modules/@paperclipai/adapter-opencode-local/dist/server/runtime-config.js|// LOCAL-PATCH 0019c"
  "0019d|$here/0019d-opencode-boxed-environment-test.patch|node_modules/@paperclipai/adapter-opencode-local/dist/server/test.js|// LOCAL-PATCH 0019d"
  "0025|$here/0025-sandbox-env-scrub.patch|node_modules/@paperclipai/adapter-utils/dist/server-utils.js|// LOCAL-PATCH 0025"
  "0026|$here/0026-claude-boxed-adapter.patch|node_modules/@paperclipai/adapter-claude-local/dist/server/execute.js|// LOCAL-PATCH 0026"
  "0026b|$here/0026b-claude-test-probe-project-settings.patch|node_modules/@paperclipai/adapter-claude-local/dist/server/test.js|// LOCAL-PATCH 0026b"
  "0026c|$here/0026c-claude-acp-probe-project-settings.patch|node_modules/@paperclipai/adapter-claude-local/dist/server/acp.js|// LOCAL-PATCH 0026c"
  "0027|$here/0027-adapter-test-board-only.patch|node_modules/@paperclipai/server/dist/routes/agents.js|// LOCAL-PATCH 0027"
)
# Resolve per-version patch files; drop optional entries that do not exist for this version.
resolved=()
for entry in "${patches[@]}"; do
  IFS='|' read -r id patch rel marker opt <<<"$entry"
  if [ -f "${patch%.patch}.$vkey.patch" ]; then patch="${patch%.patch}.$vkey.patch"
  elif [ ! -f "$patch" ]; then
    if [[ ",$opt," == *",$vkey,"* ]]; then echo "$id: not needed for $ver (skipped)"; continue; fi
    echo "$id: no patch file for $ver" >&2; exit 1
  fi
  resolved+=("$id|$patch|$rel|$marker")
done
patches=("${resolved[@]}")
scratch=$(mktemp -d "${TMPDIR:-/tmp}/paperclip-patch.XXXXXX"); trap 'rm -rf "$scratch"' EXIT

# Phase 1: classify every patch against the real tree (read-only). Patches stack on one file (0003 then 0003b, 0016 then 0026, ...),
# so an applied patch can only be reversed after the ones applied on top of it: per file, the applied patches (marker present) are
# reversed newest first on a scratch copy; every reverse must fit, which proves that exactly these patches are applied and complete.
declare -A state; bad=0; pending=()
declare -A seen_rel
for entry in "${patches[@]}"; do
  IFS='|' read -r id patch rel marker <<<"$entry"
  file="$tree/$rel"
  if [ ! -f "$file" ]; then echo "$id: MISSING target $rel" >&2; state[$id]=bad; bad=1; continue; fi
  if grep -qF -- "$marker" "$file"; then state[$id]=marked; else state[$id]=pending; pending+=("$entry"); fi
done
for ((i=${#patches[@]}-1; i>=0; i--)); do
  entry="${patches[$i]}"
  IFS='|' read -r id patch rel marker <<<"$entry"
  [ "${state[$id]:-}" = marked ] || continue
  if [ -z "${seen_rel[$rel]:-}" ]; then mkdir -p "$scratch/rev/$(dirname "$rel")"; cp -p "$tree/$rel" "$scratch/rev/$rel"; seen_rel[$rel]=1; fi
  if patch -p1 -R -F0 -s --no-backup-if-mismatch -d "$scratch/rev" <"$patch" >/dev/null 2>&1; then state[$id]=applied; echo "$id: already applied"
  else echo "$id: marker present but the patch is only partly applied or is an older version of it ($rel); restore from $rel.orig and re-run" >&2; state[$id]=bad; bad=1; fi
done

# Phase 2: trial-apply every pending patch in order on a scratch copy, so interactions between patches are caught too.
if [ $bad -eq 0 ] && [ ${#pending[@]} -gt 0 ]; then
  for entry in "${pending[@]}"; do
    IFS='|' read -r id patch rel marker <<<"$entry"
    mkdir -p "$scratch/trial/$(dirname "$rel")"; [ -e "$scratch/trial/$rel" ] || cp -p "$tree/$rel" "$scratch/trial/$rel"
    if patch -p1 -N -F0 -s --no-backup-if-mismatch -d "$scratch/trial" <"$patch" >/dev/null 2>&1 && grep -qF -- "$marker" "$scratch/trial/$rel"; then
      echo "$id: pending (applies cleanly)"
    else
      echo "$id: DOES NOT APPLY CLEANLY to $rel (Paperclip changed; patch needs a rebase)." >&2; bad=1; break
    fi
  done
fi
if [ $bad -ne 0 ]; then echo "apply.sh: at least one patch does not fit; NOTHING was changed" >&2; exit 1; fi
[ ${#pending[@]} -eq 0 ] && exit 0
[ "$mode" = check ] && exit 3

# Phase 3: apply for real; on any failure put every touched file back.
for entry in "${pending[@]}"; do
  IFS='|' read -r id patch rel marker <<<"$entry"
  [ -e "$scratch/undo/$rel" ] || { mkdir -p "$scratch/undo/$(dirname "$rel")"; cp -p "$tree/$rel" "$scratch/undo/$rel"; }
done
for entry in "${pending[@]}"; do
  IFS='|' read -r id patch rel marker <<<"$entry"
  file="$tree/$rel"; [ -e "$file.orig" ] || cp -p "$file" "$file.orig"
  if patch -p1 -N -F0 -s --no-backup-if-mismatch -d "$tree" <"$patch" && grep -qF -- "$marker" "$file"; then
    echo "$id: applied (backup $rel.orig)"
  else
    echo "$id: apply FAILED, restoring every touched file" >&2
    (cd "$scratch/undo" && find . -type f) | while read -r f; do cp -p "$scratch/undo/$f" "$tree/$f"; done
    exit 1
  fi
done
exit 0
