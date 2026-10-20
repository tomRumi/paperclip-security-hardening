// Install-wide site settings of the hardening plugin, and the settings file the patched Paperclip code reads.
// Pure Node (no SDK imports) so the worker, the CLI and the tests share it.
//
// Settings (kept in plugin state, scope "instance"; edited on the Hardening page by instance admins):
//   baseAllowlist        network allowlist every new claude_local agent starts with (host or host:port)
//   baseAllowlists       the same for every other boxed type: { <adapter type>: [hosts] } (types of src/profiles.js with
//                        scopes, except claude_local, which keeps baseAllowlist so v0.1.x settings read unchanged); a type
//                        without an entry starts with its profile's default hosts
//   extraReadOnlyPaths   extra read-only paths every new claude_local agent starts with (absolute)
//   workspaceRoots       directories boxed runs may use as their workspace (absolute)
//   hermesWrapperPath    command every new hermes_local agent runs (the root-owned sandbox wrapper)
//   hermesAllowlist      HERMES_SANDBOX_ALLOW of new hermes_local agents
//   hermesReadOnlyPaths  HERMES_SANDBOX_RO of new hermes_local agents (must then list the Hermes install dirs)
//   remoteExceptions     agents an admin exempted from the box because they run on someone else's machine or outside it:
//                        [{agentId, type, reason, addedBy, addedAt}], type one of EXCEPTIONABLE_TYPES (cursor_cloud,
//                        openclaw_gateway, hermes_gateway, http, process); every other type is always refused
//   alertCompanyId / alertProjectId   where alert issues go (watchdog alerts, failed self-test, silent watchdog); also
//                        the fallback company for log entries
//   itsecHostCompanyId   the ONE company that gets the plugin-managed ITSec agent (empty: no ITSec agent anywhere); set only
//                        from inside that company's page by an admin (src/hardening.js, src/itsec.js)
//   itsecModel           the model the operator wants the ITSec agent to run (advisory: the plugin cannot change an
//                        existing agent, the page shows the PATCH); empty: the model the agent was created with
//   itsecContext         free text about this host for the agent (labels, knowledge-base project, operating rules); the
//                        plugin writes it into the agent's `itsec-context` document
//   paperclipUrl         Paperclip's URL as the host's admin reaches it (http(s)://host:port), used in the watchdog's
//                        one-line install command; empty: $PAPERCLIP_PUBLIC_URL, else http://127.0.0.1:3100
// The enabled protections are not stored here: the engine's state.json holds them, so the plugin and the fallback CLI
// share one truth (getSettings() reports them next to these values).
//
// Settings file (config.json) = the subset Paperclip itself reads, written by writeHardeningConfig() to the path the
// caller names. The plugin gets that path from the target (engine/target.js): $PAPERCLIP_HARDENING_CONFIG of the running
// Paperclip, else <its instance root>/hardening/config.json. This module never works out a path itself, because the
// plugin worker's own environment says nothing about the Paperclip instance it serves. Patches 0003 and 0005a read the
// file once at startup (0005b re-reads remoteExceptions at each spawn, so an exception applies without a restart) and trust it only in a place no agent run can write (not inside the instance's workspaces, projects
// or companies directories or a workspace root), as a 0600 file in a directory that belongs to the service user and is not
// group- or world-writable; the writer applies the same rules and refuses otherwise. An empty setting is left out of the
// file, so Paperclip uses its built-in secure default for it (see the patch headers).
import fs from "node:fs";
import path from "node:path";
import { writeFileAtomic } from "./engine/store.js";
import { PLUGIN_ID } from "./manifest.js";
import { ITSEC_MODELS } from "./itsec-declarations.js";
import { EXCEPTIONABLE_TYPES, SCOPED_TYPES } from "./profiles.js";

export const DEFAULT_SETTINGS = Object.freeze({
  baseAllowlist: [],
  baseAllowlists: {},
  extraReadOnlyPaths: [],
  workspaceRoots: [],
  hermesWrapperPath: "",
  hermesAllowlist: [],
  hermesReadOnlyPaths: [],
  remoteExceptions: [],
  alertCompanyId: "",
  alertProjectId: "",
  paperclipUrl: "",
  itsecHostCompanyId: "",
  itsecModel: "",
  itsecContext: "",
});

/** The settings keys that belong to the ITSec agent (saved from its own card, applied by src/itsec.js). */
export const ITSEC_SETTING_KEYS = Object.freeze(["itsecHostCompanyId", "itsecModel", "itsecContext"]);
export const MAX_ITSEC_CONTEXT = 8000;

/** Keys of the settings file, in file order. */
export const CONFIG_KEYS = ["workspaceRoots", "baseAllowlist", "extraReadOnlyPaths", "hermesWrapperPath", "hermesAllowlist", "hermesReadOnlyPaths", "baseAllowlists", "remoteExceptions"];

const LIST_KEYS = ["baseAllowlist", "extraReadOnlyPaths", "workspaceRoots", "hermesAllowlist", "hermesReadOnlyPaths"];
const PATH_LIST_KEYS = new Set(["extraReadOnlyPaths", "workspaceRoots", "hermesReadOnlyPaths"]);
const MAX_LIST = 64;
const MAX_EXCEPTIONS = 256;
const MAX_REASON = 500;
const MAX_ADDED_BY = 200;
const ID_RE = /^[A-Za-z0-9-]{1,64}$/;
const ISO_TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
/** Types with their own allowlist in baseAllowlists (claude_local has baseAllowlist). */
const ALLOWLIST_TYPES = SCOPED_TYPES.filter((t) => t !== "claude_local");

export function validPath(p) {
  return path.isAbsolute(p) && !p.includes("\0") && !/[,:]/.test(p) && !p.split("/").includes("..") && p.length <= 4096;
}
// host or host:port, exact (no wildcards, no URLs): a base allowlist entry for every new agent should be a plain host.
export function validHost(h) {
  const m = /^([A-Za-z0-9.-]{1,253})(?::([0-9]{1,5}))?$/.exec(h);
  if (!m || !m[1].split(".").every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label))) return false;
  return m[2] === undefined || (Number(m[2]) >= 1 && Number(m[2]) <= 65535);
}

/** One list setting (array or newline/comma separated text) as a clean list; problems go to `errors` under `label`. */
function cleanList(label, value, isPath, errors) {
  if (value === undefined || value === null) return [];
  const raw = typeof value === "string" ? value.split(/[\n,]/) : Array.isArray(value) ? value : null;
  if (!raw) { errors.push(`${label}: must be a list`); return []; }
  const items = raw.map((v) => (typeof v === "string" ? v.trim() : v)).filter((v) => v !== "");
  const bad = items.filter((v) => typeof v !== "string" || !(isPath ? validPath(v) : validHost(v)));
  if (bad.length) errors.push(`${label}: ${isPath ? "not an absolute path (no commas, colons or ..)" : "not a host or host:port"}: ${bad.map(String).join(", ")}`);
  const clean = [...new Set(items.filter((v) => !bad.includes(v)).map((v) => (isPath ? path.normalize(v).replace(/(.)\/+$/, "$1") : v)))];
  if (clean.length > MAX_LIST) errors.push(`${label}: at most ${MAX_LIST} entries`);
  return clean.slice(0, MAX_LIST);
}

/** baseAllowlists: { type: hosts } for the boxed types other than claude_local, in profile order, empty lists left out. */
function cleanBaseAllowlists(value, errors) {
  if (value === undefined || value === null) return {};
  if (typeof value !== "object" || Array.isArray(value)) { errors.push("baseAllowlists: must be an object of adapter type to host list"); return {}; }
  const unknown = Object.keys(value).filter((t) => !ALLOWLIST_TYPES.includes(t));
  if (unknown.length) errors.push(`baseAllowlists: not a boxed adapter type with its own allowlist (${ALLOWLIST_TYPES.join(", ")}; claude_local uses baseAllowlist): ${unknown.join(", ")}`);
  const out = {};
  for (const type of ALLOWLIST_TYPES) {
    const hosts = cleanList(`baseAllowlists.${type}`, value[type], false, errors);
    if (hosts.length) out[type] = hosts;
  }
  return out;
}

/** remoteExceptions: complete entries only, one per agent (the first wins), always in the key order of the file. */
function cleanRemoteExceptions(value, errors) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) { errors.push("remoteExceptions: must be a list"); return []; }
  const out = [];
  const seen = new Set();
  value.forEach((e, i) => {
    const bad = (why) => errors.push(`remoteExceptions[${i}]: ${why}`);
    if (!e || typeof e !== "object" || Array.isArray(e)) return bad("must be an object {agentId, type, reason, addedBy, addedAt}");
    const f = (k) => (typeof e[k] === "string" ? e[k].trim() : "");
    const entry = { agentId: f("agentId"), type: f("type"), reason: f("reason"), addedBy: f("addedBy"), addedAt: f("addedAt") };
    if (!ID_RE.test(entry.agentId)) return bad("agentId is not a valid id");
    if (!EXCEPTIONABLE_TYPES.includes(entry.type)) return bad(`type must be one of ${EXCEPTIONABLE_TYPES.join(", ")} (every other type is always refused)`);
    if (!entry.reason || entry.reason.length > MAX_REASON || entry.reason.includes("\0")) return bad(`reason is required, at most ${MAX_REASON} characters`);
    if (!entry.addedBy || entry.addedBy.length > MAX_ADDED_BY || entry.addedBy.includes("\0")) return bad(`addedBy is required, at most ${MAX_ADDED_BY} characters`);
    if (!ISO_TIME_RE.test(entry.addedAt) || Number.isNaN(Date.parse(entry.addedAt))) return bad("addedAt must be an ISO 8601 date-time");
    if (seen.has(entry.agentId)) return bad(`agent ${entry.agentId} is listed twice`);
    seen.add(entry.agentId);
    out.push(entry);
  });
  if (out.length > MAX_EXCEPTIONS) errors.push(`remoteExceptions: at most ${MAX_EXCEPTIONS} entries`);
  return out.slice(0, MAX_EXCEPTIONS);
}

/**
 * Validate and clean settings. Unknown keys are dropped; lists accept arrays or newline/comma separated text.
 * @returns {{settings: object, errors: string[]}}  settings holds only valid values (invalid ones keep the default)
 */
export function normalizeSettings(input = {}) {
  const src = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const out = { ...DEFAULT_SETTINGS };
  const errors = [];
  for (const key of LIST_KEYS) out[key] = cleanList(key, src[key], PATH_LIST_KEYS.has(key), errors);
  out.baseAllowlists = cleanBaseAllowlists(src.baseAllowlists, errors);
  out.remoteExceptions = cleanRemoteExceptions(src.remoteExceptions, errors);
  const str = (key, ok, msg) => {
    const v = typeof src[key] === "string" ? src[key].trim() : src[key] === undefined || src[key] === null ? "" : null;
    if (v === null || (v !== "" && !ok(v))) { errors.push(`${key}: ${msg}`); return DEFAULT_SETTINGS[key]; }
    return v;
  };
  out.hermesWrapperPath = str("hermesWrapperPath", validPath, "must be an absolute path");
  out.alertCompanyId = str("alertCompanyId", (v) => ID_RE.test(v), "not a valid id");
  out.alertProjectId = str("alertProjectId", (v) => ID_RE.test(v), "not a valid id");
  out.paperclipUrl = str("paperclipUrl", (v) => /^https?:\/\/[A-Za-z0-9.-]{1,253}(?::\d{1,5})?$/.test(v), "must be http(s)://host or http(s)://host:port (no path)");
  out.itsecHostCompanyId = str("itsecHostCompanyId", (v) => ID_RE.test(v), "not a valid id");
  out.itsecModel = str("itsecModel", (v) => ITSEC_MODELS.includes(v), `must be one of ${ITSEC_MODELS.join(", ")} (or empty)`);
  out.itsecContext = str("itsecContext", (v) => v.length <= MAX_ITSEC_CONTEXT && !v.includes("\0"), `at most ${MAX_ITSEC_CONTEXT} characters`);
  return { settings: out, errors };
}

/** The settings file content for these (normalized) settings: only the non-empty site values. A v0.1.1 file (only the older keys) comes out unchanged. */
export function hardeningConfigFromSettings(settings) {
  const { settings: s } = normalizeSettings(settings);
  const config = { schema: 1, writtenBy: PLUGIN_ID };
  for (const key of CONFIG_KEYS) {
    const v = s[key];
    if (Array.isArray(v) ? v.length : v && typeof v === "object" ? Object.keys(v).length : v) config[key] = v;
  }
  return config;
}

export function configText(settings) {
  return `${JSON.stringify(hardeningConfigFromSettings(settings), null, 2)}\n`;
}

/** The writer refuses to put the settings file where it could not be trusted (message: what is wrong, and where). */
export class HardeningConfigRefusal extends Error {
  constructor(message) { super(message); this.name = "HardeningConfigRefusal"; }
}

/** Subdirectories of the instance root that sandboxed runs bind read-write (the workspaces, and companies/<id>/agents/<id>/claude-runtime and codex-home). */
export const SANDBOX_WRITABLE_SUBDIRS = ["workspaces", "projects", "companies"];

const insideDir = (dir, target) => {
  const rel = path.relative(dir, target);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel));
};

/** realpath of a path that may not exist yet: the nearest existing ancestor is resolved, the rest is appended. */
function realpathLoose(p) {
  const tail = [];
  for (let cur = path.resolve(p); ; cur = path.dirname(cur)) {
    try { return path.join(fs.realpathSync(cur), ...tail.reverse()); } catch (e) { if (e.code !== "ENOENT" && e.code !== "ENOTDIR") throw e; }
    if (path.dirname(cur) === cur) return path.resolve(p);
    tail.push(path.basename(cur));
  }
}

/**
 * The directories an agent run may write, as patch 0003 allows them: the three instance subdirectories above plus the
 * workspace roots (the settings' own, and the server's PAPERCLIP_SANDBOX_WORKSPACE_ROOT: a list separated like PATH).
 * Same rule as the patched server's reader, which checks the real path of the file against exactly these.
 */
export function sandboxWritableRoots({ instanceRoot, workspaceRoots = [], sandboxRootsEnv = "" }) {
  const listed = [...workspaceRoots, ...String(sandboxRootsEnv ?? "").split(path.delimiter)].map((r) => r.trim()).filter((r) => path.isAbsolute(r)).map((r) => path.resolve(r));
  return [...SANDBOX_WRITABLE_SUBDIRS.map((d) => path.join(instanceRoot, d)), ...listed];
}

/** Throw a HardeningConfigRefusal unless `st` (an lstat) is `what` owned by uid, without the forbidden mode bits. */
function assertOwned(st, { what, file, uid, isOk, modeOk, modeText }) {
  if (!isOk(st)) throw new HardeningConfigRefusal(`${file} is not ${what}`);
  if (st.uid !== uid) throw new HardeningConfigRefusal(`${file} is not owned by the service user (uid ${uid})`);
  if (!modeOk(st.mode & 0o777)) throw new HardeningConfigRefusal(`${file} has mode ${(st.mode & 0o777).toString(8).padStart(3, "0")}; ${modeText}`);
}

/**
 * Write the settings file atomically (temp file + rename) when its content differs. The patched Paperclip trusts this
 * file for allowlists and read-only paths and ignores it unless it is in a place no agent run can write and belongs to
 * the service user, so the same is required here, before anything is written:
 *   - its real path is not inside <instanceRoot>/workspaces, /projects or /companies, nor inside a workspace root;
 *   - an existing file is a regular file (not a link) owned by the service user with mode 0600, and its directory is
 *     owned by the service user and not group- or world-writable (nothing is changed on an existing file or directory:
 *     the refusal says what to fix);
 *   - a missing directory is created with mode 0700, the file with mode 0600.
 * @param {{file: string, instanceRoot: string, sandboxRootsEnv?: string, uid?: number}} o
 *   file: absolute path of the settings file (required; there is no default); instanceRoot: the Paperclip instance root;
 *   sandboxRootsEnv: PAPERCLIP_SANDBOX_WORKSPACE_ROOT of the server, when known; uid: the service user (default: this process)
 * @returns {{file: string, changed: boolean, config: object}}
 * @throws {HardeningConfigRefusal}
 */
export function writeHardeningConfig(settings, { file, instanceRoot, sandboxRootsEnv = "", uid = process.getuid?.() } = {}) {
  if (typeof file !== "string" || !path.isAbsolute(file)) throw new Error("writeHardeningConfig needs the absolute path of the settings file");
  if (typeof instanceRoot !== "string" || !path.isAbsolute(instanceRoot)) throw new Error("writeHardeningConfig needs the absolute instance root of the Paperclip it writes for");
  if (typeof uid !== "number") throw new HardeningConfigRefusal("the owner of the settings file cannot be checked on this platform");
  file = path.normalize(file);
  const dir = path.dirname(file);
  const realDir = realpathLoose(dir);
  const realFile = path.join(realDir, path.basename(file));
  const { settings: clean } = normalizeSettings(settings);
  for (const root of sandboxWritableRoots({ instanceRoot, workspaceRoots: clean.workspaceRoots, sandboxRootsEnv })) {
    if ([root, realpathLoose(root)].some((r) => insideDir(r, file) || insideDir(r, realFile)))
      throw new HardeningConfigRefusal(`${file} lies inside ${root}, which sandboxed runs can write; agents could change it`);
  }
  const assertDir = () => assertOwned(fs.lstatSync(realDir), { what: "a directory", file: realDir, uid, isOk: (st) => st.isDirectory(), modeOk: (m) => (m & 0o022) === 0, modeText: "it must not be writable by group or others" });
  try {
    assertDir();
  } catch (e) { if (e.code !== "ENOENT") throw e; }
  let current = null;
  try {
    assertOwned(fs.lstatSync(realFile), { what: "a regular file", file: realFile, uid, isOk: (st) => st.isFile(), modeOk: (m) => m === 0o600, modeText: "it must be 0600" });
    current = fs.readFileSync(realFile, "utf8");
  } catch (e) { if (e.code !== "ENOENT") throw e; }
  const text = configText(settings);
  if (current === text) return { file, changed: false, config: JSON.parse(text) };
  fs.mkdirSync(realDir, { recursive: true, mode: 0o700 });
  assertDir();
  writeFileAtomic(realFile, text, 0o600);
  return { file, changed: true, config: JSON.parse(text) };
}
