// Install-wide site settings of the hardening plugin, and the settings file the patched Paperclip code reads.
// Pure Node (no SDK imports) so the worker, the CLI and the tests share it.
//
// Settings (kept in plugin state, scope "instance"; edited on the Hardening page by instance admins):
//   baseAllowlist        network allowlist every new claude_local agent starts with (host or host:port)
//   extraReadOnlyPaths   extra read-only paths every new claude_local agent starts with (absolute)
//   workspaceRoots       directories boxed runs may use as their workspace (absolute)
//   hermesWrapperPath    command every new hermes_local agent runs (the root-owned sandbox wrapper)
//   hermesAllowlist      HERMES_SANDBOX_ALLOW of new hermes_local agents
//   hermesReadOnlyPaths  HERMES_SANDBOX_RO of new hermes_local agents (must then list the Hermes install dirs)
//   restartUnit          systemd user unit Paperclip runs as (restart button)
//   alertCompanyId / alertProjectId   where alert issues go (watchdog alerts, failed self-test, silent watchdog); also
//                        the fallback company for log entries
//   paperclipUrl         Paperclip's URL as the host's admin reaches it (http(s)://host:port), used in the watchdog's
//                        one-line install command; empty: $PAPERCLIP_PUBLIC_URL, else http://127.0.0.1:3100
// The enabled protections are not stored here: the engine's state.json holds them, so the plugin and the fallback CLI
// share one truth (getSettings() reports them next to these values).
//
// Settings file (config.json) = the subset Paperclip itself reads, written by writeHardeningConfig():
//   path: $PAPERCLIP_HARDENING_CONFIG, else <paperclip instance root>/hardening/config.json, where the instance root is
//   $PAPERCLIP_HOME (default ~/.paperclip) + /instances/ + $PAPERCLIP_INSTANCE_ID (default "default"), the same rule
//   as Paperclip's resolvePaperclipInstanceRoot(). Patches 0003 and 0005a read it once at startup. An empty setting is
//   left out of the file, so Paperclip uses its built-in secure default for it (see the patch headers).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { writeFileAtomic } from "./engine/store.js";

export const DEFAULT_SETTINGS = Object.freeze({
  baseAllowlist: [],
  extraReadOnlyPaths: [],
  workspaceRoots: [],
  hermesWrapperPath: "",
  hermesAllowlist: [],
  hermesReadOnlyPaths: [],
  restartUnit: "paperclipai",
  alertCompanyId: "",
  alertProjectId: "",
  paperclipUrl: "",
});

/** Keys of the settings file, in file order. */
export const CONFIG_KEYS = ["workspaceRoots", "baseAllowlist", "extraReadOnlyPaths", "hermesWrapperPath", "hermesAllowlist", "hermesReadOnlyPaths"];

const LIST_KEYS = ["baseAllowlist", "extraReadOnlyPaths", "workspaceRoots", "hermesAllowlist", "hermesReadOnlyPaths"];
const PATH_LIST_KEYS = new Set(["extraReadOnlyPaths", "workspaceRoots", "hermesReadOnlyPaths"]);
const MAX_LIST = 64;
const UNIT_RE = /^[A-Za-z0-9@._:-]{1,128}$/;   // same rule as engine/restart.js
const ID_RE = /^[A-Za-z0-9-]{1,64}$/;

export function validPath(p) {
  return path.isAbsolute(p) && !p.includes("\0") && !/[,:]/.test(p) && !p.split("/").includes("..") && p.length <= 4096;
}
// host or host:port, exact (no wildcards, no URLs): a base allowlist entry for every new agent should be a plain host.
export function validHost(h) {
  const m = /^([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?$/.exec(h);
  if (!m || !m[1].split(".").every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))) return false;
  return m[2] === undefined || (Number(m[2]) >= 1 && Number(m[2]) <= 65535);
}

/**
 * Validate and clean settings. Unknown keys are dropped; lists accept arrays or newline/comma separated text.
 * @returns {{settings: object, errors: string[]}}  settings holds only valid values (invalid ones keep the default)
 */
export function normalizeSettings(input = {}) {
  const src = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const out = { ...DEFAULT_SETTINGS };
  const errors = [];
  for (const key of LIST_KEYS) {
    if (src[key] === undefined || src[key] === null) { out[key] = []; continue; }
    const raw = typeof src[key] === "string" ? src[key].split(/[\n,]/) : Array.isArray(src[key]) ? src[key] : null;
    if (!raw) { errors.push(`${key}: must be a list`); out[key] = []; continue; }
    const items = raw.map((v) => (typeof v === "string" ? v.trim() : v)).filter((v) => v !== "");
    const bad = items.filter((v) => typeof v !== "string" || !(PATH_LIST_KEYS.has(key) ? validPath(v) : validHost(v)));
    if (bad.length) errors.push(`${key}: ${PATH_LIST_KEYS.has(key) ? "not an absolute path (no commas, colons or ..)" : "not a host or host:port"}: ${bad.map(String).join(", ")}`);
    const clean = [...new Set(items.filter((v) => !bad.includes(v)).map((v) => (PATH_LIST_KEYS.has(key) ? path.normalize(v).replace(/(.)\/+$/, "$1") : v)))];
    if (clean.length > MAX_LIST) errors.push(`${key}: at most ${MAX_LIST} entries`);
    out[key] = clean.slice(0, MAX_LIST);
  }
  const str = (key, ok, msg) => {
    const v = typeof src[key] === "string" ? src[key].trim() : src[key] === undefined || src[key] === null ? "" : null;
    if (v === null || (v !== "" && !ok(v))) { errors.push(`${key}: ${msg}`); return DEFAULT_SETTINGS[key]; }
    return v;
  };
  out.hermesWrapperPath = str("hermesWrapperPath", validPath, "must be an absolute path");
  out.restartUnit = str("restartUnit", (v) => UNIT_RE.test(v), "not a valid systemd unit name") || DEFAULT_SETTINGS.restartUnit;
  out.alertCompanyId = str("alertCompanyId", (v) => ID_RE.test(v), "not a valid id");
  out.alertProjectId = str("alertProjectId", (v) => ID_RE.test(v), "not a valid id");
  out.paperclipUrl = str("paperclipUrl", (v) => /^https?:\/\/[A-Za-z0-9.-]{1,253}(?::\d{1,5})?$/.test(v), "must be http(s)://host or http(s)://host:port (no path)");
  return { settings: out, errors };
}

/** The settings file content for these (normalized) settings: only the non-empty site values. */
export function hardeningConfigFromSettings(settings) {
  const { settings: s } = normalizeSettings(settings);
  const config = { schema: 1, writtenBy: "paperclip-sandbox-hardening" };
  for (const key of CONFIG_KEYS) {
    const v = s[key];
    if (Array.isArray(v) ? v.length : v) config[key] = v;
  }
  return config;
}

/** Paperclip's instance root: $PAPERCLIP_HOME (default ~/.paperclip) + /instances/ + $PAPERCLIP_INSTANCE_ID (default
 *  "default"), the same rule as Paperclip's resolvePaperclipInstanceRoot(). */
export function resolveInstanceRoot({ env = process.env, home = os.homedir() } = {}) {
  const rawHome = env.PAPERCLIP_HOME?.trim();
  const paperclipHome = rawHome
    ? path.resolve(rawHome === "~" ? home : rawHome.startsWith("~/") ? path.join(home, rawHome.slice(2)) : rawHome)
    : path.join(home, ".paperclip");
  const instanceId = env.PAPERCLIP_INSTANCE_ID?.trim() || "default";
  if (!/^[a-zA-Z0-9_-]+$/.test(instanceId)) throw new Error(`invalid PAPERCLIP_INSTANCE_ID '${instanceId}'`);
  return path.join(paperclipHome, "instances", instanceId);
}

/** Same rule as the patched Paperclip code (patches 0003 / 0005a). */
export function resolveConfigPath({ env = process.env, home = os.homedir() } = {}) {
  if (env.PAPERCLIP_HARDENING_CONFIG) return path.resolve(env.PAPERCLIP_HARDENING_CONFIG);
  return path.join(resolveInstanceRoot({ env, home }), "hardening", "config.json");
}

export function configText(settings) {
  return `${JSON.stringify(hardeningConfigFromSettings(settings), null, 2)}\n`;
}

/**
 * Write the settings file atomically (mode 0600, directory 0700) when its content differs.
 * @returns {{file: string, changed: boolean, config: object}}
 */
export function writeHardeningConfig(settings, { file = resolveConfigPath() } = {}) {
  const text = configText(settings);
  let current = null;
  try { current = fs.readFileSync(file, "utf8"); } catch (e) { if (e.code !== "ENOENT") throw e; }
  if (current === text) return { file, changed: false, config: JSON.parse(text) };
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  writeFileAtomic(file, text, 0o600);
  return { file, changed: true, config: JSON.parse(text) };
}
