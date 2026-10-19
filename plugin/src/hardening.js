// The Hardening page's backend: settings, the settings file, and the engine actions (status, plan, apply, restart,
// restore). No SDK imports: it gets the plugin context (`ctx`) passed in, so tests use a fake one.
//
// Who may write. Paperclip's plugin bridge (POST /api/plugins/:id/actions/:key) admits ANY authenticated actor with
// access to the company the call is scoped to, agents included; only a call without a company is limited to instance
// admins (assertPluginBridgeScope). The worker gets a host-built, unforgeable actor ({type, userId, agentId, companyId})
// but no "is instance admin" flag. Write actions therefore require:
//   1. actor.type "user" (agents and system calls are always refused), and
//   2. either no company scope (the host already enforced instance admin), or the user id listed in the plugin's
//      `adminUserIds` setting of that company, which only instance admins can edit (POST /api/plugins/:id/config is
//      assertInstanceAdmin). The page shows the user id to add.
import fs from "node:fs";
import { createEngine, PROTECTIONS, getProtection } from "./engine/index.js";
import { DEFAULT_SETTINGS, normalizeSettings, resolveConfigPath, writeHardeningConfig } from "./settings.js";
import { runSelfTest as runSelfTestDefault, filesKey } from "./selftest.js";
import { raiseAlertIssue } from "./alerts.js";

export const SETTINGS_KEY = Object.freeze({ scopeKind: "instance", stateKey: "settings" });
export const CONFIG_STATE_KEY = Object.freeze({ scopeKind: "instance", stateKey: "config-written" });
/** Last self-test: {at, trigger, serverStartedAt, results: {id: {ok, mode, checks, filesKey}}, failed, alertedSignature}
 *  or {at, trigger, waitingRestart: true}. */
export const SELFTEST_KEY = Object.freeze({ scopeKind: "instance", stateKey: "selftest" });
const PLACEHOLDER_NOTE = "coming in a later step";
/** Protections whose patched code reads the settings file (a settings change needs a restart while they are on). */
const READS_CONFIG = ["own-box", "safe-defaults"];

export class NotAllowedError extends Error {
  constructor(message) { super(message); this.name = "NotAllowedError"; this.code = "NOT_ALLOWED"; }
}

const plainList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);

/** When Paperclip (this worker's parent process) started, from /proc; works for systemd, Docker, pm2 and manual runs. */
export function parentStartedAt(pid = process.ppid) {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const ticks = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19]); // field 22: starttime, in clock ticks since boot
    const btime = Number(/^btime (\d+)$/m.exec(fs.readFileSync("/proc/stat", "utf8"))[1]);
    if (!Number.isFinite(ticks) || !Number.isFinite(btime)) return undefined;
    return new Date(Math.floor((btime + ticks / 100) * 1000)).toISOString(); // USER_HZ is 100 on Linux
  } catch {
    return undefined;
  }
}

/**
 * @param {object} o
 * @param {object} o.ctx              plugin context (state, config, activity, logger)
 * @param {object} [o.engineOptions]  passed to createEngine (treeDir, dataDir, patchesDir, tmpDir, systemctl, io)
 * @param {string} [o.configPath]     settings file path (default: resolveConfigPath())
 * @param {Function} [o.createEngineFn]
 * @param {Function} [o.serverStartedAt]  () => ISO time Paperclip started, or undefined (then the engine asks systemd)
 * @param {Function} [o.runSelfTestFn]    src/selftest.js runSelfTest (tests pass their own checks)
 */
export function createHardening({ ctx, engineOptions = {}, configPath, createEngineFn = createEngine, serverStartedAt = parentStartedAt, runSelfTestFn = runSelfTestDefault } = {}) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {}, debug() {} };
  let engineCache = null;
  let availabilityCache = null;
  let queue = Promise.resolve();
  /** () => {watchdog, hermes} status of the host-installed parts (src/hostinstall.js), set by the worker. */
  let hostStatusFn = null;
  /** Serialize writes: one plan+apply at a time. */
  const exclusive = (fn) => { const run = queue.then(fn, fn); queue = run.catch(() => {}); return run; };

  async function loadSettings() {
    const stored = await ctx.state.get(SETTINGS_KEY).catch(() => null);
    return normalizeSettings(stored ?? DEFAULT_SETTINGS).settings;
  }

  const file = () => configPath ?? resolveConfigPath();

  function engineFor(settings) {
    const unitName = settings.restartUnit || DEFAULT_SETTINGS.restartUnit;
    if (!engineCache || engineCache.unitName !== unitName) {
      try { engineCache = { unitName, engine: createEngineFn({ ...engineOptions, unitName }) }; }
      catch (e) { engineCache = { unitName, error: e.message }; }
      availabilityCache = null;
    }
    if (engineCache.error) throw new Error(`the hardening engine cannot run on this install: ${engineCache.error}`);
    return engineCache.engine;
  }

  async function assertAdmin(context) {
    const actor = context?.actor ?? {};
    if (actor.type !== "user" || !actor.userId)
      throw new NotAllowedError(`only instance admins can change protections (this request came from ${actor.type === "agent" ? "an agent" : "a non-user caller"})`);
    const companyId = actor.companyId ?? null;
    if (companyId === null) return actor; // the host allowed a company-less call only for an instance admin
    const cfg = (await ctx.config.get(companyId).catch(() => null)) ?? {};
    if (plainList(cfg.adminUserIds).includes(actor.userId)) return actor;
    throw new NotAllowedError(`only instance admins can change protections. An instance admin must add your user id (${actor.userId}) to "Users who may change protections" in this plugin's settings first.`);
  }

  async function logActivity(context, settings, message, metadata) {
    const companyId = context?.companyId ?? context?.actor?.companyId ?? (settings.alertCompanyId || null);
    if (!companyId) { log.info(message, metadata); return false; }
    try {
      await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: "paperclip-sandbox-hardening", metadata });
      return true;
    } catch (e) {
      log.warn(`activity log entry not written: ${e.message}`, { message });
      return false;
    }
  }

  /** Write config.json from the settings; remembers when its content last changed (for "restart needed"). */
  async function writeConfig(settings) {
    const r = writeHardeningConfig(settings, { file: file() });
    if (r.changed) await ctx.state.set(CONFIG_STATE_KEY, { at: new Date().toISOString(), pending: true }).catch(() => {});
    return r;
  }

  /** Which patch protections fit this install (a plan with all of them on; cached per file content). */
  async function availability(engine, status) {
    const key = JSON.stringify(status.files.map((f) => f.currentSha));
    if (availabilityCache?.key !== key) {
      const plan = await engine.plan(PROTECTIONS.filter((p) => p.kind === "patch").map((p) => p.id));
      availabilityCache = { key, unavailable: plan.unavailable };
    }
    return availabilityCache.unavailable;
  }

  function summarizePlan(plan, switchedOff = []) {
    const title = (id) => getProtection(id)?.title ?? id;
    return {
      enabled: plan.enabled,
      added: plan.added.map((a) => ({ id: a.id, title: title(a.id), neededBy: a.neededBy.map(title) })),
      switchedOffDependents: switchedOff.map((d) => ({ id: d.id, title: title(d.id), because: d.because.map(title) })),
      keptOn: plan.neededOff.map((a) => ({ id: a.id, title: title(a.id), neededBy: a.neededBy.map(title) })),
      confirmationNeeded: plan.confirmationNeeded,
      protections: plan.protections.map((p) => ({ id: p.id, title: p.title, enabled: p.enabled, action: p.action, reason: p.reason })),
      unavailable: plan.unavailable,
      changes: plan.changes,
      restartNeededAfterApply: plan.restartNeededAfterApply,
    };
  }

  /** Requested set -> what to plan: protections switched off take their dependents with them (listed for the owner). */
  function resolveRequest(currentEnabled, requested) {
    const known = new Set(PROTECTIONS.filter((p) => p.kind === "patch").map((p) => p.id));
    const unknown = requested.filter((id) => !getProtection(id));
    if (unknown.length) throw new Error(`unknown protection(s): ${unknown.join(", ")}`);
    const wanted = [...new Set(requested.filter((id) => known.has(id)))];
    const off = currentEnabled.filter((id) => !wanted.includes(id));
    const needs = (id, seen = new Set()) => {
      for (const r of getProtection(id)?.requires ?? []) if (!seen.has(r)) { seen.add(r); needs(r, seen); }
      return seen;
    };
    const switchedOff = [];
    for (const id of wanted) {
      const because = [...needs(id)].filter((r) => off.includes(r));
      if (because.length) switchedOff.push({ id, because });
    }
    return { enabled: wanted.filter((id) => !switchedOff.some((d) => d.id === id)), switchedOff };
  }

  function parseEnabled(params) {
    const v = params?.enabled;
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new Error("enabled must be a list of protection ids");
    return v;
  }

  /**
   * Run the self-test against the files the running Paperclip loaded. Skipped (recorded as "waiting for restart")
   * while a restart is pending: the files on disk are then not what Paperclip runs. A failure is logged and raised
   * as an alert issue once per set of failed protections; the next fully passing run logs the recovery.
   */
  async function selfTestNow({ trigger, context = null }) {
    const settings = await loadSettings();
    const engine = engineFor(settings);
    const startedAt = serverStartedAt();
    const status = await engine.status(startedAt === undefined ? {} : { serverStartedAt: startedAt });
    const prev = await ctx.state.get(SELFTEST_KEY).catch(() => null);
    const at = new Date().toISOString();
    if (status.restartNeeded) {
      await ctx.state.set(SELFTEST_KEY, { ...(prev ?? {}), at, trigger, waitingRestart: true, results: {} });
      return { ok: true, ran: false, reason: "Paperclip has not restarted since the last change; the self-test runs after the restart" };
    }
    const r = await runSelfTestFn({ engine, status });
    const failed = Object.entries(r.results).filter(([, x]) => !x.ok).map(([id]) => id).sort();
    const signature = failed.join(",");
    let alertedSignature = prev?.alertedSignature ?? "";
    const title = (id) => getProtection(id)?.title ?? id;
    if (failed.length) {
      const lines = failed.map((id) => `- **${title(id)}** (${r.results[id].mode}): ${r.results[id].checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`).join("; ")}`);
      await logActivity(context, settings, `Sandbox hardening self-test failed: ${failed.map(title).join(", ")}`, { trigger, failed, serverStartedAt: status.serverStartedAt,
        results: Object.fromEntries(failed.map((id) => [id, r.results[id].checks.filter((c) => !c.ok)])) });
      if (alertedSignature !== signature) {
        const a = await raiseAlertIssue({ ctx, settings, priority: "high", metadata: { source: "self-test", failed },
          title: `[Sandbox hardening] Self-test failed: ${failed.map(title).join(", ")}`.slice(0, 240),
          description: `The self-test after ${trigger === "start" ? "Paperclip's start" : "a manual run"} (${at}) found switched-on protections that do not work as expected in the files Paperclip runs:\n\n${lines.join("\n")}\n\nOpen the Hardening page: the rows are red. Re-apply (Save) and restart, or check whether the Paperclip files were changed outside the plugin.` });
        if (a.ok) alertedSignature = signature;
      }
    } else if (alertedSignature) {
      await logActivity(context, settings, "Sandbox hardening self-test passes again", { trigger });
      alertedSignature = "";
    }
    await ctx.state.set(SELFTEST_KEY, { ...r, trigger, serverStartedAt: status.serverStartedAt ?? null, failed, alertedSignature, waitingRestart: false });
    return { ok: failed.length === 0, ran: true, failed, results: r.results, at: r.at };
  }

  const api = {
    assertAdmin,
    loadSettings,
    selfTestNow,
    setHostStatus(fn) { hostStatusFn = fn; },

    /** Admin action "runSelfTest" (the page's button). */
    runSelfTest(params = {}, context) {
      return exclusive(async () => {
        await assertAdmin(context);
        return selfTestNow({ trigger: "manual", context });
      });
    },

    /** After the worker started (= Paperclip (re)started): the automatic self-test. */
    selfTestAfterStart() {
      return exclusive(() => selfTestNow({ trigger: "start" }));
    },

    async getSettings() {
      const settings = await loadSettings();
      let enabled = null;
      try { enabled = (await engineFor(settings).status()).enabled; } catch { enabled = null; }
      return { settings, enabled, configPath: file() };
    },

    async getStatus() {
      const settings = await loadSettings();
      let engine;
      try { engine = engineFor(settings); }
      catch (e) {
        return { available: false, reason: e.message, protections: PROTECTIONS.map((p) => rowFor(p, null, null, null, null)), restart: null, configPath: file() };
      }
      const startedAt = serverStartedAt();
      const status = await engine.status(startedAt === undefined ? {} : { serverStartedAt: startedAt });
      const unavailable = await availability(engine, status).catch(() => ({}));
      const byId = Object.fromEntries(status.protections.map((p) => [p.id, p]));
      const st = await ctx.state.get(SELFTEST_KEY).catch(() => null);
      const withFiles = Object.fromEntries(engine.protections().map((p) => [p.id, p]));
      const selfTests = {};
      for (const [id, res] of Object.entries(st?.results ?? {})) {
        if (withFiles[id] && res?.filesKey === filesKey(withFiles[id], status.files)) selfTests[id] = { ...res, at: st.at, trigger: st.trigger };
      }
      const hosts = hostStatusFn ? await hostStatusFn().catch((e) => { log.warn(`host install status unavailable: ${e.message}`); return null; }) : null;
      const info = engine.restartInfo();
      const started = status.serverStartedAt;
      const cfgState = await ctx.state.get(CONFIG_STATE_KEY).catch(() => null);
      const configPending = Boolean(cfgState?.pending) && READS_CONFIG.some((id) => ["applied", "pending-restart"].includes(byId[id]?.status))
        && (started && cfgState.at ? Date.parse(cfgState.at) > Date.parse(started) : true);
      return {
        available: true,
        tree: status.tree,
        paperclipVersion: status.paperclipVersion,
        enabled: status.enabled,
        protections: PROTECTIONS.map((p) => rowFor(p, byId[p.id], unavailable[p.id] ?? null, selfTests[p.id] ?? null, hosts)),
        selfTest: st ? { at: st.at ?? null, trigger: st.trigger ?? null, waitingRestart: Boolean(st.waitingRestart), failed: st.failed ?? [] } : null,
        watchdog: hosts?.watchdog ?? null,
        hermes: hosts?.hermes ?? null,
        files: status.files.map((f) => ({ rel: f.rel, state: f.state })),
        restart: {
          needed: status.restartNeeded || configPending,
          settingsChanged: configPending,
          canRestart: info.canRestart,
          commandText: info.commandText,
          reason: info.reason ?? null,
          startedAt: started,
        },
        configPath: file(),
      };
    },

    async planChange(params = {}, context) {
      if (context?.actor?.type === "agent") throw new NotAllowedError("agents cannot plan protection changes");
      const settings = await loadSettings();
      const engine = engineFor(settings);
      const current = (await engine.status()).enabled;
      const req = resolveRequest(current, parseEnabled(params));
      const plan = await engine.plan(req.enabled, { repair: params.repair === true, adoptOrig: params.adoptOrig === true });
      return summarizePlan(plan, req.switchedOff);
    },

    applyChange(params = {}, context) {
      return exclusive(async () => {
        const actor = await assertAdmin(context);
        const settings = await loadSettings();
        const engine = engineFor(settings);
        const before = (await engine.status()).enabled;
        const req = resolveRequest(before, parseEnabled(params));
        const plan = await engine.plan(req.enabled, { repair: params.repair === true, adoptOrig: params.adoptOrig === true });
        const result = await engine.apply(plan, { confirmCoreOff: params.confirmCoreOff === true });
        availabilityCache = null;
        const summary = summarizePlan(plan, req.switchedOff);
        if (!result.ok) return { ok: false, error: result.error, plan: summary };
        const after = (await engine.status()).enabled;
        const changedSet = before.join(",") !== after.join(",");
        if (result.changed.length || changedSet) {
          const turnedOn = after.filter((id) => !before.includes(id));
          const turnedOff = before.filter((id) => !after.includes(id));
          await logActivity(context, settings,
            `Sandbox hardening changed: ${[...turnedOn.map((id) => `+${id}`), ...turnedOff.map((id) => `-${id}`)].join(" ") || "files rebuilt"}${result.restartNeeded ? " (restart needed)" : ""}`,
            { userId: actor.userId, enabled: after, turnedOn, turnedOff, changedFiles: result.changed, unavailable: Object.keys(result.unavailable ?? {}), confirmCoreOff: params.confirmCoreOff === true });
        }
        return { ok: true, changed: result.changed, applied: result.applied, unavailable: result.unavailable, restartNeeded: result.restartNeeded, plan: summary };
      });
    },

    restart(params = {}, context) {
      return exclusive(async () => {
        const actor = await assertAdmin(context);
        const settings = await loadSettings();
        const engine = engineFor(settings);
        const info = engine.restartInfo();
        if (!info.canRestart)
          return { ok: false, manual: true, message: `Restart Paperclip now (${info.reason ?? "it does not run as a systemd user unit here"}).` };
        // Logged first: the restart stops this worker together with Paperclip.
        await logActivity(context, settings, `Sandbox hardening: Paperclip restart requested (${info.commandText})`, { userId: actor.userId });
        await ctx.state.set(CONFIG_STATE_KEY, { at: new Date().toISOString(), pending: false }).catch(() => {});
        const r = await engine.restart({ noBlock: true });
        return { ok: r.ok, output: r.output, commandText: info.commandText };
      });
    },

    restoreAll(params = {}, context) {
      return exclusive(async () => {
        const actor = await assertAdmin(context);
        if (params.confirm !== true) return { ok: false, error: "restoring the originals needs confirmation (confirm: true)" };
        const settings = await loadSettings();
        const engine = engineFor(settings);
        const r = await engine.restoreAll({ force: params.force === true });
        availabilityCache = null;
        if (r.ok) await logActivity(context, settings, `Sandbox hardening: all protections switched off, original Paperclip files restored${r.restartNeeded ? " (restart needed)" : ""}`,
          { userId: actor.userId, restored: r.restored, skipped: r.skipped });
        return r;
      });
    },

    saveSettings(params = {}, context) {
      return exclusive(async () => {
        const actor = await assertAdmin(context);
        const { settings, errors } = normalizeSettings(params.settings);
        if (errors.length) return { ok: false, errors };
        await ctx.state.set(SETTINGS_KEY, settings);
        const r = await writeConfig(settings);
        if (r.changed) await logActivity(context, settings, "Sandbox hardening: site settings changed", { userId: actor.userId, configPath: r.file, config: r.config });
        return { ok: true, settings, configPath: r.file, configChanged: r.changed };
      });
    },

    /**
     * On worker start: write the settings file, then rebuild the switched-on set against the current Paperclip files
     * (after a Paperclip update this adopts the new originals) and apply it. Only when the engine already manages this
     * install (something is switched on); a tree it never touched (or one patched by apply.sh) is left alone.
     */
    start() {
      return exclusive(async () => {
        const settings = await loadSettings();
        // Only once an admin saved settings: never replace a settings file written by hand before the plugin was set up.
        const saved = await ctx.state.get(SETTINGS_KEY).catch(() => null);
        const cfg = saved === null ? null
          : await writeConfig(settings).catch((e) => { log.error(`cannot write the hardening settings file: ${e.message}`); return null; });
        let engine;
        try { engine = engineFor(settings); } catch (e) { log.warn(e.message); return { ok: false, error: e.message, config: cfg }; }
        const enabled = (await engine.status()).enabled;
        if (!enabled.length) return { ok: true, applied: false, reason: "nothing switched on", config: cfg };
        const plan = await engine.replan();
        if (!plan.changes) return { ok: true, applied: false, reason: "files already match", config: cfg };
        const result = await engine.apply(plan);
        availabilityCache = null;
        if (!result.ok) { log.error(`re-applying the protections failed: ${result.error}`); return { ok: false, error: result.error, config: cfg }; }
        const refreshed = plan.files.filter((f) => f.pristineSource === "refreshed").map((f) => f.rel);
        await logActivity(null, settings, `Sandbox hardening re-applied after start${refreshed.length ? " (Paperclip files changed, e.g. an update)" : ""}; restart Paperclip to activate`,
          { changedFiles: result.changed, refreshedOriginals: refreshed, unavailable: Object.keys(result.unavailable ?? {}) });
        return { ok: true, applied: true, changed: result.changed, unavailable: result.unavailable, config: cfg };
      });
    },
  };
  return api;
}

/** Protections that run inside the plugin and are set somewhere else (no switch on this page). */
const MANAGED_ELSEWHERE = { "daily-caps": "Runs every 5 minutes; set per company on the Agent boxes page (enforce, report only or off)." };

/** Host-installed rows: status from src/hostinstall.js. */
const HOST_ROWS = {
  watchdog: (h) => h?.watchdog && { status: h.watchdog.status, enabled: h.watchdog.status !== "off",
    reason: h.watchdog.status === "on" ? `last heartbeat ${h.watchdog.lastHeartbeatAt}`
      : h.watchdog.status === "silent" ? `no heartbeat since ${h.watchdog.lastHeartbeatAt} (more than 30 minutes)`
        : h.watchdog.status === "waiting" ? "waiting for the watchdog to report in" : "not installed" },
  "hermes-boxed": (h) => h?.hermes && { status: h.hermes.status, enabled: h.hermes.status !== "off", reason: `${h.hermes.path}: ${h.hermes.reason}` },
};

function rowFor(p, st, unavailableReason, selfTest = null, hosts = null) {
  const host = HOST_ROWS[p.id]?.(hosts);
  if (host) {
    return { id: p.id, title: p.title, description: p.description, kind: p.kind, core: p.core, risk: p.risk ?? null, requires: p.requires,
      defaultOn: p.defaultOn, enabled: host.enabled, status: host.status, reason: host.reason, placeholder: false, hostInstall: true };
  }
  if (MANAGED_ELSEWHERE[p.id]) {
    return { id: p.id, title: p.title, description: p.description, kind: p.kind, core: p.core, risk: p.risk ?? null, requires: p.requires,
      defaultOn: p.defaultOn, enabled: true, status: "on", reason: MANAGED_ELSEWHERE[p.id], placeholder: false, managedElsewhere: true };
  }
  const placeholder = p.kind !== "patch";
  let status;
  if (placeholder) status = "placeholder";
  else if (!st) status = "unknown";
  else if (st.status === "off") status = unavailableReason ? "unavailable" : "off";
  else status = st.status; // applied | pending-restart | unavailable | drifted
  let reason = placeholder ? PLACEHOLDER_NOTE : (st?.reason ?? unavailableReason ?? null);
  if (status === "applied" && selfTest && !selfTest.ok) {
    status = "selftest-failed";
    reason = selfTest.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`).join("; ");
  }
  return {
    id: p.id, title: p.title, description: p.description, kind: p.kind, core: p.core, risk: p.risk ?? null, requires: p.requires,
    defaultOn: p.defaultOn, enabled: Boolean(st && st.status !== "off"), status,
    reason,
    placeholder,
    selfTest: status === "applied" || status === "selftest-failed" ? (selfTest ? { ok: selfTest.ok, mode: selfTest.mode, at: selfTest.at, checks: selfTest.checks } : null) : null,
  };
}
