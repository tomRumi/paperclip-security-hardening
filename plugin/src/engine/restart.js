// Restart hook: find out whether Paperclip runs as a systemd USER unit that this account may restart itself.
// detectRestart() only reads (`systemctl --user show`); runRestart() is the only thing that restarts, and only on request.
import fs from "node:fs";
import { spawnSync } from "node:child_process";

/** `systemctl --user` needs XDG_RUNTIME_DIR, which Paperclip's plugin workers do not get; add the standard one. */
export function userManagerEnv(env = process.env) {
  if (env.XDG_RUNTIME_DIR || typeof process.getuid !== "function") return env;
  const dir = `/run/user/${process.getuid()}`;
  return fs.existsSync(dir) ? { ...env, XDG_RUNTIME_DIR: dir } : env;
}

/**
 * @param {object} opts
 * @param {string} [opts.unitName]  systemd user unit (no default: the caller says which one)
 * @param {string|null} [opts.systemctl]  null disables detection (e.g. in tests)
 * @param {string} [opts.expectCgroup]  control group the Paperclip server process runs in (from /proc/<pid>/cgroup). With
 *        it the unit only counts when systemd reports exactly that group and the server is the unit's main process
 *        (or a member of the group): a unit of the same name that does not run THIS Paperclip is never restarted.
 * @param {number} [opts.parentPid]  pid of the Paperclip server process (with expectCgroup)
 * @param {string} [opts.cgroupRoot]  where the cgroup file system is mounted
 * @returns {{canRestart: boolean, command: string[]|null, commandText: string|null, unit: string|null, startedAt: string|null, reason?: string}}
 */
export function detectRestart({ unitName, systemctl = "systemctl", expectCgroup, parentPid, cgroupRoot = "/sys/fs/cgroup" } = {}) {
  const base = { canRestart: false, command: null, commandText: null, unit: unitName ?? null, startedAt: null };
  if (!systemctl) return { ...base, reason: "restart detection disabled" };
  if (!unitName) return { ...base, reason: "no restart unit known" };
  if (!/^[A-Za-z0-9@._:-]+$/.test(unitName)) return { ...base, reason: "invalid unit name" };
  const r = spawnSync(systemctl, ["--user", "show", unitName, "--property=LoadState,ActiveState,ExecMainStartTimestamp,ControlGroup,MainPID", "--timestamp=unix"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 10_000, env: userManagerEnv() });
  if (r.error || r.status !== 0) return { ...base, reason: "no systemd user manager here; restart Paperclip by hand (Docker, pm2, manual)" };
  const props = Object.fromEntries(r.stdout.split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  if (props.LoadState !== "loaded" || props.ActiveState !== "active")
    return { ...base, reason: `systemd user unit ${unitName} is not active (LoadState=${props.LoadState}, ActiveState=${props.ActiveState})` };
  if (expectCgroup !== undefined) {
    if (props.ControlGroup !== expectCgroup) return { ...base, reason: `systemd user unit ${unitName} does not run this Paperclip (its control group is not the one the server is in); restart Paperclip by hand` };
    if (!(Number(props.MainPID) === parentPid || cgroupHasPid(cgroupRoot, expectCgroup, parentPid)))
      return { ...base, reason: `the Paperclip server process is not part of systemd user unit ${unitName}; restart Paperclip by hand` };
  }
  const ts = /^@(\d+)/.exec(props.ExecMainStartTimestamp ?? "");
  const command = ["systemctl", "--user", "restart", unitName];
  return { ...base, canRestart: true, command, commandText: command.join(" "), startedAt: ts ? new Date(Number(ts[1]) * 1000).toISOString() : null };
}

function cgroupHasPid(root, cgroup, pid) {
  try { return fs.readFileSync(`${root}${cgroup}/cgroup.procs`, "utf8").split("\n").includes(String(pid)); } catch { return false; }
}

/** Run the restart command from detectRestart(). Never called by the engine itself. noBlock: queue the job and return
 *  (`systemctl --user --no-block restart ...`), for callers that are themselves stopped by the restart. */
export function runRestart(info, { noBlock = false } = {}) {
  if (!info?.canRestart || !Array.isArray(info.command)) throw new Error("no restart command available");
  const [cmd, ...rest] = info.command;
  const args = noBlock && rest[0] === "--user" ? ["--user", "--no-block", ...rest.slice(1)] : rest;
  const r = spawnSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 120_000, env: userManagerEnv() });
  return { ok: r.status === 0, output: `${r.stdout ?? ""}${r.stderr ?? ""}`.trim() };
}
