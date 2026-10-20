// Which Paperclip instance the engine works on. The plugin worker is a plain fork of the Paperclip server and gets neither
// PAPERCLIP_HOME, the instance id nor a home directory of that instance, so nothing in the worker's own environment can
// name the install. The target is derived from the server process instead (/proc/<ppid>): the tree it runs from, its
// instance id and data directory (command-line flags win over its start-up environment, as in Paperclip), the settings
// file its patched code reads and the systemd user unit it runs in. Anything unclear is a refusal, never a default.
// Dependency-free (Node 20+ built-ins). The standalone CLI (bin/hardening-engine.mjs) builds explicit targets from the
// same layout rules (describeInstanceLayout).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

/** Directory (inside the Paperclip home) that holds the engine's pristine copies, state and events. */
export const DATA_LEAF = "sandbox-hardening";
const INSTANCE_ID_RE = /^[a-zA-Z0-9_-]+$/; // Paperclip's PATH_SEGMENT_RE
const TREE_SCRIPT_RE = /^(.+)\/node_modules\/paperclipai\/dist\/index\.js$/;
/** The only variables read from the server's start-up environment; every other value is dropped unread. */
const ENV_KEYS = ["HOME", "PAPERCLIP_HOME", "PAPERCLIP_INSTANCE_ID", "PAPERCLIP_CONFIG", "PAPERCLIP_HARDENING_CONFIG", "PAPERCLIP_SANDBOX_WORKSPACE_ROOT", "PAPERCLIP_DISABLE_CWD_ENV_FILE", "RUN_LOG_BASE_PATH", "PAPERCLIP_DEPLOYMENT_MODE"];
/** `node` options that take a value in the next argument (everything else starting with `-` stands alone). */
const NODE_VALUE_OPTIONS = new Set(["-r", "--require", "--import", "--loader", "--experimental-loader", "-C", "--conditions", "--input-type", "--title"]);
/** `node` options that load a file into the server's environment (`--env-file X`, `--env-file=X`, `--env-file-if-exists ...`); /proc/<pid>/environ never shows what they set. */
const NODE_ENV_FILE_OPTION_RE = /^--env-file(-if-exists)?(=|$)/;
/** Variables of which only the fact that they are set is kept (never the value): dotenv switches to an encrypted `.env.vault` while DOTENV_KEY is non-empty. */
const PRESENCE_KEYS = ["DOTENV_KEY"];
/** The only variables read from a `.env` file that Paperclip loads (the file is parsed for these and nothing else). */
const DOTENV_KEYS = ["PAPERCLIP_HOME", "PAPERCLIP_INSTANCE_ID", "PAPERCLIP_CONFIG", "PAPERCLIP_HARDENING_CONFIG", "PAPERCLIP_SANDBOX_WORKSPACE_ROOT", "PAPERCLIP_DISABLE_CWD_ENV_FILE", "RUN_LOG_BASE_PATH", "PAPERCLIP_DEPLOYMENT_MODE"];
/** Of those, the ones that decide which instance a server is: a value that only a `.env` file gives is not followed. */
const INSTANCE_KEYS = ["PAPERCLIP_HOME", "PAPERCLIP_INSTANCE_ID", "PAPERCLIP_CONFIG"];
const RUN_FLAGS = { "-i": "instance", "--instance": "instance", "-d": "dataDir", "--data-dir": "dataDir", "-c": "config", "--config": "config" };
const FIX = "use the command-line tool (plugin/bin/hardening-engine.mjs) with --tree and --data";

/** code: NO_PARENT | FOREIGN_UID | PROC_UNREADABLE | UNKNOWN_LAUNCHER | NO_TREE | STALE_LAUNCH | BAD_INSTANCE | CONFIG_LAYOUT |
 *  BAD_CONFIG_PATH | INSTANCE_MISMATCH | TARGET_CHANGED. evidence: facts only (paths, flag names, variable names), never the value of a variable or of a flag. */
export class TargetError extends Error {
  constructor(code, message, evidence = []) { super(message); this.name = "TargetError"; this.code = code; this.evidence = evidence; }
}

/** Paperclip's unit name for an instance (`paperclipai service install`). */
export const systemdServiceName = (instanceId) => (instanceId === "default" ? "paperclipai.service" : `paperclipai-${instanceId}.service`);

export function expandHomePrefix(value, userHome) {
  if (value === "~") return userHome;
  if (value.startsWith("~/")) return path.resolve(userHome, value.slice(2));
  return value;
}

/**
 * Paperclip's own path rules for one instance (resolvePaperclipHomeDir / InstanceId / InstanceRoot), without reading any
 * environment: the caller passes what it knows. home and instanceId are already resolved (absolute / valid).
 */
export function describeInstanceLayout({ home, instanceId }) {
  if (typeof instanceId !== "string" || !INSTANCE_ID_RE.test(instanceId)) throw new TargetError("BAD_INSTANCE", "the instance id is invalid (letters, digits, - and _ only; the value is not shown)");
  if (typeof home !== "string" || !path.isAbsolute(home)) throw new TargetError("BAD_INSTANCE", "the Paperclip home is not an absolute path (the value is not shown)");
  const instanceRoot = path.join(home, "instances", instanceId);
  return {
    home, instanceId, instanceRoot,
    serverConfigPath: path.join(instanceRoot, "config.json"),
    dataDir: path.join(home, DATA_LEAF),
    configPath: path.join(instanceRoot, "hardening", "config.json"),
    runLogBase: path.join(instanceRoot, "data", "run-logs"),
    unit: systemdServiceName(instanceId),
  };
}

const trimmed = (v) => (typeof v === "string" ? v.trim() : "");

/** Instance id and home the way `paperclipai run` resolves them: a flag wins over the start-up environment. */
export function resolveInstanceInputs({ flags = {}, env = {}, userHome, cwd }) {
  const rawHome = trimmed(flags.dataDir) || trimmed(env.PAPERCLIP_HOME);
  const home = rawHome ? path.resolve(cwd, expandHomePrefix(rawHome, userHome)) : path.resolve(userHome, ".paperclip");
  const instanceId = trimmed(flags.instance) || trimmed(env.PAPERCLIP_INSTANCE_ID) || "default";
  return { home, instanceId };
}

// ------------------------------------------------------------------------------------------------ /proc parsing

/** /proc/<pid>/cmdline -> argv (NUL separated, one trailing NUL); null when empty. */
export function parseCmdline(buf) {
  const text = Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf ?? "");
  if (!text) return null;
  const parts = text.split("\0");
  if (parts[parts.length - 1] === "") parts.pop();
  return parts.length ? parts : null;
}

/** The value of a presence-only variable as it is kept: "1" when non-empty, else "" (still set, so a `.env` cannot give it). */
const presence = (value) => (value.length > 0 ? "1" : "");

/** /proc/<pid>/environ -> only the wanted variables (the rest is never kept); PRESENCE_KEYS are reduced to whether they are non-empty. */
export function parseEnviron(buf, keys = ENV_KEYS) {
  const out = {};
  for (const entry of buf.toString("utf8").split("\0")) {
    const eq = entry.indexOf("=");
    if (eq <= 0) continue;
    const key = entry.slice(0, eq);
    if (keys.includes(key)) out[key] = entry.slice(eq + 1);
    else if (PRESENCE_KEYS.includes(key)) out[key] = presence(entry.slice(eq + 1));
  }
  return out;
}

/**
 * `node [node options] <script> run [options]` -> {script, flags: {instance, dataDir, config}, flagNames}.
 * Only the `paperclipai run` launch is understood; anything else (another subcommand, a wrapper, tsx, a different
 * script) is an unknown launcher.
 */
export function parseServerCommand(argv) {
  const unknown = (why) => new TargetError("UNKNOWN_LAUNCHER", `cannot tell which Paperclip this is: ${why}; ${FIX}`);
  let i = 1;
  while (i < argv.length && argv[i].startsWith("-") && argv[i] !== "-") {
    if (NODE_ENV_FILE_OPTION_RE.test(argv[i])) throw unknown("node was started with an --env-file option, which sets variables that /proc does not show (the file and its values are not read)");
    i += NODE_VALUE_OPTIONS.has(argv[i]) ? 2 : 1;
  }
  const script = argv[i];
  if (!script) throw unknown("the server process has no script argument");
  const rest = argv.slice(i + 1);
  if (rest[0] !== "run") throw unknown("the server was not started with `paperclipai run`");
  const flags = {};
  const flagNames = [];
  for (let k = 1; k < rest.length; k++) {
    const a = rest[k];
    if (a === "--") break;
    let name = a;
    let inline;
    if (a.startsWith("--")) { const eq = a.indexOf("="); if (eq >= 0) { name = a.slice(0, eq); inline = a.slice(eq + 1); } }
    else if (/^-[icd]./.test(a)) { name = a.slice(0, 2); inline = a.slice(2); }
    if (RUN_FLAGS[name]) {
      const value = inline ?? rest[++k];
      if (value === undefined) throw unknown(`${name} has no value`);
      flags[RUN_FLAGS[name]] = value;
      flagNames.push(name);
    } else if (name === "--bind" && inline === undefined) k++;
  }
  return { script, flags, flagNames };
}

/**
 * /proc/<pid>/cgroup -> {path, unit, cgroup, reason}. Only cgroup v2 and a `.service` below `user@<uid>.service` count as
 * "a systemd user service"; the unit's own control group is the path up to and including that segment.
 */
export function parseCgroup(text, uid) {
  const lines = String(text ?? "").split("\n").filter(Boolean);
  const none = (reason, cg = null) => ({ path: cg, unit: null, cgroup: null, reason });
  if (lines.length !== 1 || !lines[0].startsWith("0::")) return none("not a pure cgroup v2 host, so the systemd unit cannot be verified");
  const cg = lines[0].slice(3);
  const segs = cg.split("/").filter(Boolean);
  const at = segs.indexOf(`user@${uid}.service`);
  if (at < 0) return none("Paperclip does not run inside this user's systemd manager", cg);
  let last = -1;
  for (let k = at + 1; k < segs.length; k++) if (segs[k].endsWith(".service")) last = k;
  if (last < 0) return none("Paperclip does not run as a systemd user service", cg);
  return { path: cg, unit: segs[last], cgroup: `/${segs.slice(0, last + 1).join("/")}`, reason: null };
}

/** Field 22 of /proc/<pid>/stat (start time in clock ticks since boot). */
export function readStartTicks(statText) {
  const ticks = Number(statText.slice(statText.lastIndexOf(")") + 2).split(" ")[19]);
  return Number.isFinite(ticks) ? ticks : null;
}

/** ISO start time of a process; undefined when it cannot be computed. USER_HZ is 100 on Linux. */
export function startedAtFromTicks(ticks, procStatText) {
  const btime = Number(/^btime (\d+)$/m.exec(procStatText ?? "")?.[1]);
  if (!Number.isFinite(ticks) || !Number.isFinite(btime)) return undefined;
  return new Date(Math.floor((btime + ticks / 100) * 1000)).toISOString();
}

const sha = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

// dotenv 17.4.2 (lib/main.js): the LINE pattern and the value rules of parse(), which `paperclipai run` and the server use for
// every `.env` they load. Kept verbatim so a file is read exactly as Paperclip reads it.
const DOTENV_LINE = /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/mg;

/** One key out of a dotenv file, as dotenv's parse() reads it (last occurrence wins); no other value is kept. */
export function readDotenvKey(text, key) {
  const lines = String(text).replace(/\r\n?/mg, "\n");
  const line = new RegExp(DOTENV_LINE.source, DOTENV_LINE.flags); // its own lastIndex
  let value;
  for (let match; (match = line.exec(lines)) != null;) {
    if (match[1] !== key) continue;
    let v = (match[2] || "").trim();
    const maybeQuote = v[0];
    v = v.replace(/^(['"`])([\s\S]*)\1$/mg, "$2");
    if (maybeQuote === '"') v = v.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
    value = v;
  }
  return value;
}

// ------------------------------------------------------------------------------------------------ derivation

function readProc(fsx, procRoot, pid, name, { link = false } = {}) {
  const file = path.join(procRoot, String(pid), name);
  try { return link ? fsx.readlinkSync(file) : fsx.readFileSync(file); }
  catch (e) {
    throw new TargetError("PROC_UNREADABLE", `cannot read ${name} of the Paperclip server process (pid ${pid}): ${e.code ?? e.message}. It is gone, or /proc hides it (hidepid); ${FIX}`, [`${procRoot}/${pid}/${name}: ${e.code ?? e.message}`]);
  }
}

/** Newest symlink on the way to `file` that was changed after the process started (null when none). */
function symlinkChangedAfter(fsx, file, startedMs) {
  let pending = file.split("/").filter(Boolean);
  let cur = "/";
  for (let hops = 0; pending.length;) {
    const seg = pending.shift();
    if (seg === ".") continue;
    if (seg === "..") { cur = path.dirname(cur); continue; }
    const next = path.join(cur, seg);
    const st = fsx.lstatSync(next);
    if (!st.isSymbolicLink()) { cur = next; continue; }
    if (++hops > 40) throw new TargetError("NO_TREE", `too many symlinks in ${file}`);
    if (st.ctimeMs > startedMs) return next;
    const to = fsx.readlinkSync(next);
    pending = to.split("/").filter(Boolean).concat(pending);
    if (to.startsWith("/")) cur = "/";
  }
  return null;
}

/** Paperclip's resolveConfigPath: the flag, PAPERCLIP_CONFIG, a .paperclip/config.json at or above the cwd, else the instance's own. */
function paperclipConfigPath({ flag, env, cwd, fsx, layout }) {
  if (flag) return path.resolve(cwd, flag);
  if (env.PAPERCLIP_CONFIG) return path.resolve(cwd, env.PAPERCLIP_CONFIG);
  for (let dir = cwd; ; dir = path.dirname(dir)) {
    const candidate = path.join(dir, ".paperclip", "config.json");
    if (fsx.existsSync(candidate)) return candidate;
    if (path.dirname(dir) === dir) break;
  }
  return layout().serverConfigPath;
}

/**
 * What `paperclipai run` makes of its start-up environment, flags and `.env` files, in Paperclip's order: the --data-dir
 * override, then the `.env` beside the config resolved WITHOUT --instance (so possibly the default instance's), then the
 * instance (flag, else environment), home and config, then the `.env` beside that config, and last (the server module
 * loads it) the `.env` in the working directory, unless PAPERCLIP_DISABLE_CWD_ENV_FILE is "true" or it is the file just
 * loaded. A `.env` never overrides a variable that is already set, even to an empty value, so the first source that has a
 * key wins. Returns the instance's layout, the config the server reads, PAPERCLIP_HARDENING_CONFIG,
 * PAPERCLIP_SANDBOX_WORKSPACE_ROOT (a workspace root the settings-file writer must keep clear of) and RUN_LOG_BASE_PATH
 * (as given: the server reads it untrimmed, after every load). A value that only a `.env` file gives for the home, the
 * instance or the config, and that Paperclip then uses (an empty value, or a value a flag overrides, is not used), is a
 * CONFIG_LAYOUT refusal: it is not followed. Values are never put into a message.
 */
function resolveRunStartup({ flags, env: startEnv, userHome, cwd, fsx, evidence }) {
  const env = { ...startEnv }; // the server's environment as the steps below would leave it
  const fromDotenv = new Map(); // INSTANCE_KEYS key -> the .env file whose value Paperclip uses
  const loaded = new Set();
  const loadFile = (file) => {
    if (loaded.has(file) || !fsx.existsSync(file)) return;
    loaded.add(file);
    // dotenv's config() reads the encrypted `<file>.vault` instead of the file while DOTENV_KEY is non-empty (only its presence is tracked).
    if (env.DOTENV_KEY && fsx.existsSync(`${file}.vault`)) throw new TargetError("CONFIG_LAYOUT", `DOTENV_KEY is set while Paperclip loads ${file}, and ${file}.vault exists, so dotenv reads the encrypted vault instead; its contents cannot be followed (the value is not shown); ${FIX}`, [...evidence, `${file}.vault with DOTENV_KEY set`]);
    let text;
    try { text = fsx.readFileSync(file, "utf8"); } catch { return; }
    const dotenvKey = readDotenvKey(text, "DOTENV_KEY");
    if (dotenvKey !== undefined && !Object.hasOwn(env, "DOTENV_KEY")) env.DOTENV_KEY = presence(dotenvKey); // a later file may now be a vault
    for (const key of DOTENV_KEYS) {
      const value = readDotenvKey(text, key);
      if (value === undefined || Object.hasOwn(env, key)) continue;
      env[key] = value;
      // Used by Paperclip: the home and the instance id are trimmed and fall back when empty, the config path is used unless empty.
      if (INSTANCE_KEYS.includes(key) && (key === "PAPERCLIP_CONFIG" ? value !== "" : value.trim() !== "")) fromDotenv.set(key, file);
    }
  };
  const envFileBeside = (configPath) => path.join(path.dirname(configPath), ".env");
  const inputs = (instance) => resolveInstanceInputs({ flags: { instance }, env, userHome, cwd });
  const layoutFor = (instance) => describeInstanceLayout(inputs(instance));

  if (trimmed(flags.dataDir)) { // applyDataDirOverride
    env.PAPERCLIP_HOME = path.resolve(cwd, expandHomePrefix(trimmed(flags.dataDir), userHome));
    if (!trimmed(flags.config) && !trimmed(env.PAPERCLIP_CONFIG)) {
      const layout = layoutFor(flags.instance);
      env.PAPERCLIP_INSTANCE_ID = layout.instanceId;
      env.PAPERCLIP_CONFIG = layout.serverConfigPath;
    }
  }
  loadFile(envFileBeside(paperclipConfigPath({ flag: flags.config, env, cwd, fsx, layout: () => layoutFor(undefined) }))); // loadPaperclipEnvFile(options.config)
  const layout = layoutFor(flags.instance); // runCommand
  env.PAPERCLIP_INSTANCE_ID = layout.instanceId;
  if (trimmed(flags.instance)) fromDotenv.delete("PAPERCLIP_INSTANCE_ID"); // the flag decided, not the .env
  const serverConfig = paperclipConfigPath({ flag: flags.config, env, cwd, fsx, layout: () => layout });
  env.PAPERCLIP_CONFIG = serverConfig;
  if (flags.config) fromDotenv.delete("PAPERCLIP_CONFIG");
  loadFile(envFileBeside(serverConfig));

  // @paperclipai/server config.js, once the server module is imported: the .env in the working directory.
  const serverEnv = envFileBeside(serverConfig);
  const cwdEnv = path.resolve(cwd, ".env");
  if (env.PAPERCLIP_DISABLE_CWD_ENV_FILE !== "true" && fsx.existsSync(cwdEnv)) {
    let sameFile;
    try { sameFile = fsx.existsSync(serverEnv) ? fsx.realpathSync(cwdEnv) === fsx.realpathSync(serverEnv) : cwdEnv === serverEnv; } catch { sameFile = false; }
    if (!sameFile) loadFile(cwdEnv);
  }

  const [dotenvLayout] = fromDotenv;
  if (dotenvLayout) {
    const [key, file] = dotenvLayout;
    throw new TargetError("CONFIG_LAYOUT", `${key} is set only in ${file}, which Paperclip loads; the instance cannot be told from a start-up environment that does not hold it (the value is not shown); ${FIX}`, [...evidence, `${key} in ${file}`]);
  }
  return { layout, serverConfig, hardeningConfig: env.PAPERCLIP_HARDENING_CONFIG, sandboxRootsEnv: env.PAPERCLIP_SANDBOX_WORKSPACE_ROOT, runLogBasePath: env.RUN_LOG_BASE_PATH, deploymentModeEnv: env.PAPERCLIP_DEPLOYMENT_MODE };
}

/** The server's resolveDeploymentMode: PAPERCLIP_DEPLOYMENT_MODE when valid, else `server.deploymentMode` of its config file, else
 *  "local_trusted" (also without a config file). null when the config file cannot be read or says something else (not guessed). */
function deploymentModeOf(fromEnv, serverConfigPath, fsx) {
  const MODES = ["local_trusted", "authenticated"];
  if (MODES.includes(fromEnv)) return fromEnv;
  let text;
  try { text = fsx.readFileSync(serverConfigPath, "utf8"); } catch (e) { return e?.code === "ENOENT" ? "local_trusted" : null; }
  try {
    const mode = JSON.parse(text)?.server?.deploymentMode;
    return mode === undefined || mode === null ? "local_trusted" : MODES.includes(mode) ? mode : null;
  } catch { return null; }
}

function derive({ pid, procRoot, uid, userHome: passwdHome, fsx }) {
  if (!Number.isInteger(pid) || pid <= 1) throw new TargetError("NO_PARENT", `this worker has no Paperclip server parent (pid ${pid}); ${FIX}`);
  const ev = [`server pid ${pid}`];
  const read = (name, opts) => readProc(fsx, procRoot, pid, name, opts);

  const status = read("status").toString("utf8");
  const ids = /^Uid:\s+(\d+)\s+(\d+)/m.exec(status);
  if (!ids || Number(ids[1]) !== uid || Number(ids[2]) !== uid) throw new TargetError("FOREIGN_UID", `the Paperclip server process (pid ${pid}) does not run as the same user as this plugin worker`, ev);
  const exe = path.basename(read("exe", { link: true }).replace(/ \(deleted\)$/, ""));
  if (!/^node(js)?$/.test(exe)) throw new TargetError("UNKNOWN_LAUNCHER", `the Paperclip server process runs ${exe}, not node; ${FIX}`, [...ev, `exe ${exe}`]);

  const cmdBuf = read("cmdline");
  const argv = parseCmdline(cmdBuf);
  if (!argv) throw new TargetError("PROC_UNREADABLE", `the command line of the Paperclip server process (pid ${pid}) is empty; ${FIX}`, ev);
  const { script, flags, flagNames } = parseServerCommand(argv);
  const cwd = read("cwd", { link: true });
  const rawScript = path.resolve(cwd, script);
  let realScript;
  try { realScript = fsx.realpathSync(rawScript); } catch { throw new TargetError("NO_TREE", `the server script ${rawScript} no longer exists; restart Paperclip`, [...ev, `script ${rawScript}`]); }
  const m = TREE_SCRIPT_RE.exec(realScript);
  const evidence = [...ev, `script ${realScript}`, `flags ${flagNames.join(" ") || "(none)"}`];
  if (!m) throw new TargetError("UNKNOWN_LAUNCHER", `unsupported server layout (${realScript} is not <tree>/node_modules/paperclipai/dist/index.js); ${FIX}`, evidence);
  const tree = m[1];
  try {
    if (JSON.parse(fsx.readFileSync(path.join(tree, "node_modules/@paperclipai/server/package.json"), "utf8")).name !== "@paperclipai/server") throw new Error("wrong package");
  } catch { throw new TargetError("NO_TREE", `${tree} holds no @paperclipai/server package; ${FIX}`, evidence); }

  const statText = read("stat").toString("utf8");
  const startTicks = readStartTicks(statText);
  let procStat = "";
  try { procStat = fsx.readFileSync(path.join(procRoot, "stat"), "utf8"); } catch { /* start time stays unknown */ }
  const startedAt = startedAtFromTicks(startTicks, procStat);
  if (startTicks === null || !startedAt) throw new TargetError("PROC_UNREADABLE", `cannot read the start time of the Paperclip server process (pid ${pid}); ${FIX}`, evidence);
  const changed = symlinkChangedAfter(fsx, rawScript, Date.parse(startedAt));
  if (changed) throw new TargetError("STALE_LAUNCH", `${changed} was changed after Paperclip started, so the files on disk are not what is running; restart Paperclip first`, evidence);

  const env = parseEnviron(read("environ"));
  const userHome = trimmed(env.HOME) || passwdHome || os.userInfo().homedir; // the home the server itself sees
  if (!path.isAbsolute(userHome ?? "")) throw new TargetError("BAD_INSTANCE", "the Paperclip server has no usable home directory", evidence);
  const { layout, serverConfig, hardeningConfig, sandboxRootsEnv, runLogBasePath, deploymentModeEnv } = resolveRunStartup({ flags, env, userHome, cwd, fsx, evidence });
  const { instanceId } = layout;
  if (serverConfig !== layout.serverConfigPath)
    throw new TargetError("CONFIG_LAYOUT", `the server reads its config (chosen by -c, PAPERCLIP_CONFIG or a .paperclip/config.json above its working directory) from outside its instance folder ${layout.serverConfigPath}; ${FIX}`, evidence);
  try {
    const info = JSON.parse(fsx.readFileSync(path.join(layout.instanceRoot, "runtime-info.json"), "utf8"));
    if (info?.pid === pid && info.instanceId !== instanceId) throw new TargetError("INSTANCE_MISMATCH", `the server says it runs another instance than '${instanceId}'; ${FIX}`, evidence);
  } catch (e) { if (e instanceof TargetError) throw e; /* absent or unreadable: corroboration only */ }

  let configPath = layout.configPath;
  if (hardeningConfig) { // the patched server reads it as is (no trimming), from its environment or the first .env that has it
    if (!path.isAbsolute(hardeningConfig) || hardeningConfig.includes("\0")) throw new TargetError("BAD_CONFIG_PATH", "PAPERCLIP_HARDENING_CONFIG of the server is not an absolute path", evidence);
    configPath = path.normalize(hardeningConfig);
  }

  const cg = parseCgroup(read("cgroup").toString("utf8"), uid);
  let restart;
  if (!cg.unit) restart = { unit: null, reason: cg.reason };
  else if (cg.unit !== layout.unit) restart = { unit: null, reason: `the unit ${cg.unit} is not Paperclip's own name for instance '${instanceId}' (${layout.unit}); restart Paperclip by hand` };
  else restart = { unit: cg.unit, cgroup: cg.cgroup, pid };

  return {
    source: "server-process", pid, startedAt, tree, script: realScript, userHome,
    home: layout.home, instanceId, instanceRoot: layout.instanceRoot, serverConfigPath: layout.serverConfigPath,
    dataDir: layout.dataDir, configPath, deploymentMode: deploymentModeOf(deploymentModeEnv, layout.serverConfigPath, fsx), sandboxRootsEnv: sandboxRootsEnv ?? "",
    runLogBase: runLogBasePath === undefined ? layout.runLogBase : path.resolve(cwd, runLogBasePath), // `??` and path.resolve in the server's run-log store
    restart, fingerprint: { pid, startTicks, cmdlineSha: sha(cmdBuf) },
  };
}

/**
 * The target of this plugin worker: the Paperclip server process that started it.
 * @param {object} [o]  pid (default: parent), procRoot, uid, userHome (home when the server's environment has none; default: the
 *   account's passwd entry), fsImpl: injectable for tests
 * @returns {{ok: true, target: object} | {ok: false, code: string, reason: string, evidence: string[]}}
 */
export function resolveTargetFromParent({ pid = process.ppid, procRoot = "/proc", uid = process.getuid?.(), userHome, fsImpl = fs } = {}) {
  try {
    return { ok: true, target: derive({ pid, procRoot, uid, userHome, fsx: fsImpl }) };
  } catch (e) {
    if (e instanceof TargetError) return { ok: false, code: e.code, reason: e.message, evidence: e.evidence };
    return { ok: false, code: "INTERNAL", reason: `cannot work out which Paperclip this is: ${e.message}; ${FIX}`, evidence: [] };
  }
}

/** Is the process the target was derived from still the same one (same pid, start time and command line)? */
export function verifyTarget(target, { procRoot = "/proc", fsImpl = fs } = {}) {
  const fp = target?.fingerprint;
  if (!fp) return { ok: true }; // an explicit (command-line) target is not bound to a process
  const gone = (why) => ({ ok: false, code: "TARGET_CHANGED", reason: `the Paperclip server process (pid ${fp.pid}) ${why}; restart this plugin together with Paperclip` });
  try {
    const ticks = readStartTicks(fsImpl.readFileSync(path.join(procRoot, String(fp.pid), "stat"), "utf8"));
    if (ticks !== fp.startTicks) return gone("is not the process this worker was started by");
    if (sha(fsImpl.readFileSync(path.join(procRoot, String(fp.pid), "cmdline"))) !== fp.cmdlineSha) return gone("changed its command line");
  } catch { return gone("is gone"); }
  return { ok: true };
}

/** The target as the Hardening page shows it (paths and ids only). */
export function summarizeTarget(target) {
  return {
    source: target.source, pid: target.pid ?? null, tree: target.tree, instanceId: target.instanceId ?? null, home: target.home ?? null,
    instanceRoot: target.instanceRoot ?? null, dataDir: target.dataDir, configPath: target.configPath,
    deploymentMode: target.deploymentMode ?? null,
    restartUnit: target.restart?.unit ?? null, restartNote: target.restart?.unit ? null : (target.restart?.reason ?? null),
  };
}
