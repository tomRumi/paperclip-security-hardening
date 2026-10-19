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
 * @param {{unitName?: string, systemctl?: string|null}} opts  systemctl: null disables detection (e.g. in tests)
 * @returns {{canRestart: boolean, command: string[]|null, commandText: string|null, unit: string, startedAt: string|null, reason?: string}}
 */
export function detectRestart({ unitName = "paperclipai", systemctl = "systemctl" } = {}) {
  const base = { canRestart: false, command: null, commandText: null, unit: unitName, startedAt: null };
  if (!systemctl) return { ...base, reason: "restart detection disabled" };
  if (!/^[A-Za-z0-9@._:-]+$/.test(unitName)) return { ...base, reason: "invalid unit name" };
  const r = spawnSync(systemctl, ["--user", "show", unitName, "--property=LoadState,ActiveState,ExecMainStartTimestamp", "--timestamp=unix"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 10_000, env: userManagerEnv() });
  if (r.error || r.status !== 0) return { ...base, reason: "no systemd user manager here; restart Paperclip by hand (Docker, pm2, manual)" };
  const props = Object.fromEntries(r.stdout.split("\n").filter((l) => l.includes("=")).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
  if (props.LoadState !== "loaded" || props.ActiveState !== "active")
    return { ...base, reason: `systemd user unit ${unitName} is not active (LoadState=${props.LoadState}, ActiveState=${props.ActiveState})` };
  const ts = /^@(\d+)/.exec(props.ExecMainStartTimestamp ?? "");
  const command = ["systemctl", "--user", "restart", unitName];
  return { ...base, canRestart: true, command, commandText: command.join(" "), startedAt: ts ? new Date(Number(ts[1]) * 1000).toISOString() : null };
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
