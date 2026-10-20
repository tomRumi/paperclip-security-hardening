#!/usr/bin/env bash
# Re-apply the local Paperclip sandbox patches after an update. rc 0: patched (restarts paperclipai only if it applied something).
# rc 1: a patch does not fit -> NO restart; opens ONE Paperclip issue naming the failed patch(es).
# --dry-run: print the issue payload instead of posting it, do not apply or restart.
# Configuration (environment, e.g. a systemd user unit Environment= or EnvironmentFile=):
#   PAPERCLIP_SECURITY_APPLY       path to host/patches/apply.sh          (default: ../patches/apply.sh next to this script)
#   PAPERCLIP_API_URL              Paperclip base URL, e.g. http://PAPERCLIP_HOST:3100   (required to open the issue)
#   PAPERCLIP_ALERT_COMPANY_ID     company that receives the issue        (required to open the issue)
#   PAPERCLIP_ALERT_PROJECT_ID     project for the issue                  (optional)
#   PAPERCLIP_ALERT_ASSIGNEE_ID    agent id to assign the issue to        (optional)
#   PAPERCLIP_ALERT_TOKEN_FILE     file (mode 0600) with the API token of a LOW-PRIVILEGE company member (role Operator or lower) that
#                                  may create issues. Do NOT use a board/admin token: this file lives in the agent user's home.
#                                  Alternative: leave unset (no issue is opened) and rely on the plugin page and the watchdog.
#   PAPERCLIP_SECURITY_STATE_DIR   default $HOME/.local/state/paperclip-patch-reapply
#   PAPERCLIP_SECURITY_STATUS_FILE patch-status.json for the Paperclip plugin (default $STATE_DIR/patch-status.json);
#                                  point the plugin's "hardening-status" folder at its directory
set -uo pipefail
A=${PAPERCLIP_SECURITY_APPLY:-$(cd "$(dirname "$0")" && pwd)/../patches/apply.sh}
STATE=${PAPERCLIP_SECURITY_STATE_DIR:-$HOME/.local/state/paperclip-patch-reapply}; mkdir -p "$STATE"
export STATE
tree=$(readlink -f "$HOME/.paperclip/cli/current"); log=$(mktemp); trap 'rm -f "$log"' EXIT
dry=0; [ "${1:-}" = "--dry-run" ] && dry=1
run_apply() {
  "$A" --check >"$log" 2>&1; rc=$?
  [ $rc -eq 0 ] && { applied=0; return 0; }
  [ $rc -eq 3 ] && { "$A" >"$log" 2>&1; rc=$?; applied=1; }
  return $rc
}
if [ $dry -eq 1 ]; then rc=1; echo "0003: DOES NOT APPLY CLEANLY (dry-run)" >"$log"
else
  run_apply; rc=$?
  if [ $rc -eq 1 ]; then sleep 90; run_apply; rc=$?; fi   # an update may still be writing the tree: retry once
fi
cat "$log"
# status snapshot for the (read-only) Paperclip plugin
SF=${PAPERCLIP_SECURITY_STATUS_FILE:-$STATE/patch-status.json}
res=failed; [ $rc -eq 0 ] && { res=ok; [ "${applied:-0}" = 1 ] && res=applied; }
failed_json=$(grep -oE '^00[0-9]{2}[a-e]?: (DOES NOT|MISSING|marker|apply FAILED)' "$log" | cut -d: -f1 | sort -u | awk 'BEGIN{printf "["} {printf "%s\"%s\"", (NR>1?",":""), $0} END{printf "]"}')
[ $rc -eq 0 ] && failed_json='[]'
printf '{"checked_at":"%s","version":"%s","result":"%s","failed":%s}\n' "$(date -u +%FT%TZ)" "$(basename "$tree")" "$res" "$failed_json" > "$SF.tmp" && mv "$SF.tmp" "$SF"
if [ $rc -eq 0 ]; then
  rm -f "$STATE/reported-for"
  if [ "${applied:-0}" = 1 ]; then echo "patches applied on $tree; restarting paperclipai"; systemctl --user restart paperclipai; fi
  exit 0
fi
# ---- failure: no restart; open one issue per tree ----
[ $dry -eq 0 ] && [ "$(cat "$STATE/reported-for" 2>/dev/null)" = "$tree" ] && { echo "already reported for $tree"; exit 1; }
# the board token is never passed in argv (readable from /proc by every local user): the python block reads it from its file, on the live path only
python3 -I - "$tree" "$log" "$dry" <<'PY'
import json, os, re, sys, urllib.request
tree, logf, dry = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
api, company = os.environ.get("PAPERCLIP_API_URL", "").rstrip("/"), os.environ.get("PAPERCLIP_ALERT_COMPANY_ID", "")
log = open(logf).read()
failed = sorted(set(re.findall(r"^(00[0-9]{2}[a-e]?): (?:DOES NOT|MISSING|marker|apply FAILED)", log, re.M)))
ver = tree.rsplit("/", 1)[-1]
body = {
  "status": "todo", "priority": "high",
  "title": f"Paperclip security patch {', '.join(failed) or '?'} does not apply to Paperclip {ver}",
  "description": ("Paperclip was updated to **" + ver + "** and the security patch(es) **" + (", ".join(failed) or "unknown") +
    "** no longer apply. Paperclip was NOT restarted; agents keep running on the tree that is already loaded.\n\n"
    "apply.sh output:\n```\n" + log[-3000:] + "\n```\n\n"
    "Task: rebase the failed patch(es) against the new upstream code (same `// LOCAL-PATCH 00NN` markers) and comment with the paths. "
    "The host install is outside the agent sandbox; the admin re-runs apply.sh after review.")
}
if os.environ.get("PAPERCLIP_ALERT_PROJECT_ID"): body["projectId"] = os.environ["PAPERCLIP_ALERT_PROJECT_ID"]
if os.environ.get("PAPERCLIP_ALERT_ASSIGNEE_ID"): body["assigneeAgentId"] = os.environ["PAPERCLIP_ALERT_ASSIGNEE_ID"]
if dry: print(json.dumps(body, indent=1)); sys.exit(0)
tokfile = os.environ.get("PAPERCLIP_ALERT_TOKEN_FILE", "")
if not (api and company and tokfile):
    print("PAPERCLIP_API_URL / PAPERCLIP_ALERT_COMPANY_ID / PAPERCLIP_ALERT_TOKEN_FILE not set: no issue opened", file=sys.stderr); sys.exit(2)
board = open(tokfile).read().strip()
req = urllib.request.Request(f"{api}/api/companies/{company}/issues", data=json.dumps(body).encode(), method="POST",
      headers={"Content-Type": "application/json", "Authorization": "Bearer " + board})
try:
    r = json.load(urllib.request.urlopen(req, timeout=30)); print("issue created:", r.get("identifier") or r.get("id"))
    open(os.path.join(os.environ["STATE"], "reported-for"), "w").write(tree)
except Exception as e:
    print("ISSUE CREATION FAILED:", e, file=sys.stderr); sys.exit(2)
PY
exit 1
