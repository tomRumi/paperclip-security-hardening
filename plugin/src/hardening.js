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
//
// Which Paperclip. Everything the engine changes (tree, data dir, settings file, restart unit) comes from the target,
// derived from the Paperclip server process that started this worker (src/engine/target.js). When it cannot be derived
// the page says why and every action that would change anything refuses; nothing falls back to the default install.
import { createEngine, PROTECTIONS, getProtection } from "./engine/index.js";
import { resolveTargetFromParent, verifyTarget, summarizeTarget } from "./engine/target.js";
import { DEFAULT_SETTINGS, HardeningConfigRefusal, ITSEC_SETTING_KEYS, normalizeSettings, writeHardeningConfig } from "./settings.js";
import { runSelfTest as runSelfTestDefault, filesKey } from "./selftest.js";
import { raiseAlertIssue } from "./alerts.js";
import { PLUGIN_ID } from "./manifest.js";

export const SETTINGS_KEY = Object.freeze({ scopeKind: "instance", stateKey: "settings" });
export const CONFIG_STATE_KEY = Object.freeze({ scopeKind: "instance", stateKey: "config-written" });
/** Last self-test: {at, trigger, serverStartedAt, results: {id: {ok, mode, checks, filesKey}}, failed, alertedSignature}
 *  or {at, trigger, waitingRestart: true}. */
export const SELFTEST_KEY = Object.freeze({ scopeKind: "instance", stateKey: "selftest" });
/** Last "target unknown" alert raised: {code} (cleared once the target resolves again). */
export const TARGET_ALERT_KEY = Object.freeze({ scopeKind: "instance", stateKey: "target-alert" });
/** Set while a Paperclip update (or a new patch set) left a switched-on core protection that no longer fits:
 *  {at, paperclipVersion, signature, alerted, held, accepted, protections: [{id, title, risk, reason, held}]}. Every protection that still
 *  fits is applied anyway; the one that does not is skipped but stays enabled. `held` = the protection is in the files now and the rebuild
 *  would remove it: then nothing is rebuilt at all until an admin decides (Save asks for the confirmation). Cleared by the next start that
 *  finds everything fitting; `accepted` = an admin confirmed dropping it (no new alert for the same set and version). */
export const UPDATE_DECISION_KEY = Object.freeze({ scopeKind: "instance", stateKey: "update-decision" });
/** Protections whose change Paperclip now contains itself (informational heads-up, no alert): {signature, at, paperclipVersion, protections: [{id, title, patches}]}. */
export const UPSTREAM_KEY = Object.freeze({ scopeKind: "instance", stateKey: "now-upstream" });
/** Set once the HIGH alert for "the instance runs in local_trusted mode" was raised ({alerted: true}); cleared when it does not any more. */
export const LOCAL_TRUSTED_KEY = Object.freeze({ scopeKind: "instance", stateKey: "local-trusted-alert" });
export const LOCAL_TRUSTED_TEXT = "This Paperclip runs in local_trusted mode: any caller without a token is treated as the board, including a boxed agent that reaches the server's API (for example on localhost). The sandbox cannot make such a call safe.";
const PLACEHOLDER_NOTE = "coming in a later step";
/** Protections whose patched code reads the settings file (a settings change needs a restart while they are on). */
const READS_CONFIG = ["own-box", "safe-defaults"];

/** How to restart Paperclip when the plugin cannot do it (no verified systemd user unit). */
export const MANUAL_RESTART_HOW = 'Stop it and start it again the way you started it: press Ctrl-C in the terminal that runs "paperclipai run" and run the same command again, or run "paperclipai service restart" if Paperclip runs as its own service.';
export function manualRestartText(reason) {
  return `The plugin cannot restart Paperclip itself${reason ? ` (${reason})` : ""}. ${MANUAL_RESTART_HOW}`;
}

/** Why a restart is needed (Paperclip's patched code loads its files and the settings file once, at startup). */
function restartWhy({ filesChanged, settingsChanged }) {
  if (settingsChanged && filesChanged) return "Protection files were rebuilt and the settings file changed. Paperclip reads both only when it starts.";
  if (settingsChanged) return "Only the settings file changed, but the patched Paperclip reads it once at startup, so the new values apply after a restart.";
  return "Paperclip loads the rebuilt files only when it starts.";
}

export class NotAllowedError extends Error {
  constructor(message) { super(message); this.name = "NotAllowedError"; this.code = "NOT_ALLOWED"; }
}

/** The worker cannot tell which Paperclip it serves (or the server process it was derived from is gone). */
export class TargetUnknownError extends Error {
  constructor({ code, reason }) { super(reason); this.name = "TargetUnknownError"; this.code = "TARGET_UNKNOWN"; this.targetCode = code; }
}

const plainList = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : []);

/**
 * @param {object} o
 * @param {object} o.ctx              plugin context (state, config, activity, logger)
 * @param {object} [o.engineOptions]  passed to createEngine besides the target's own values (patchesDir, tmpDir, systemctl, io)
 * @param {Function} [o.resolveTargetFn]  () => {ok, target} | {ok: false, code, reason}; default: the Paperclip server process
 * @param {Function} [o.verifyTargetFn]   (target) => {ok} | {ok: false, code, reason}; is the target's process still the same
 * @param {Function} [o.createEngineFn]
 * @param {Function} [o.serverStartedAt]  (target) => ISO time Paperclip started, or undefined (then the engine asks systemd)
 * @param {Function} [o.runSelfTestFn]    src/selftest.js runSelfTest (tests pass their own checks)
 */
export function createHardening({ ctx, engineOptions = {}, resolveTargetFn = resolveTargetFromParent, verifyTargetFn = verifyTarget, createEngineFn = createEngine,
  serverStartedAt = (target) => target.startedAt, runSelfTestFn = runSelfTestDefault } = {}) {
  const log = ctx.logger ?? { info() {}, warn() {}, error() {}, debug() {} };
  let targetCache = null;
  let lastTargetFailure = null;
  let engineCache = null;
  let availabilityCache = null;
  let queue = Promise.resolve();
  /** () => {watchdog, hermes} status of the host-installed parts (src/hostinstall.js), set by the worker. */
  let hostStatusFn = null;
  /** The ITSec agent service (src/itsec.js), set by the worker; the ITSec settings need it. */
  let itsec = null;
  /** Serialize writes: one plan+apply at a time. */
  const exclusive = (fn) => { const run = queue.then(fn, fn); queue = run.catch(() => {}); return run; };

  async function loadSettings() {
    const stored = await ctx.state.get(SETTINGS_KEY).catch(() => null);
    return normalizeSettings(stored ?? DEFAULT_SETTINGS).settings;
  }

  /**
   * The Paperclip this worker serves. Resolved on first use and kept; failures are not kept (the next call asks again).
   * revalidate: the server process must still be the one the target came from (call before anything that writes).
   * @throws {TargetUnknownError}
   */
  function requireTarget({ revalidate = false } = {}) {
    if (!targetCache) {
      const r = resolveTargetFn();
      if (!r.ok) {
        if (lastTargetFailure !== r.code) log.warn(`cannot tell which Paperclip this worker serves (${r.code}): ${r.reason}`, { evidence: r.evidence });
        lastTargetFailure = r.code;
        throw new TargetUnknownError(r);
      }
      lastTargetFailure = null;
      targetCache = r.target;
    }
    if (revalidate) {
      const v = verifyTargetFn(targetCache);
      if (!v.ok) { targetCache = null; engineCache = null; availabilityCache = null; throw new TargetUnknownError(v); }
    }
    return targetCache;
  }

  function engineFor() {
    const target = requireTarget();
    const key = JSON.stringify([target.tree, target.dataDir, target.restart]);
    if (!engineCache || engineCache.key !== key) {
      try { engineCache = { key, engine: createEngineFn({ ...engineOptions, treeDir: target.tree, dataDir: target.dataDir, restart: target.restart, refuseTreeChange: true }) }; }
      catch (e) { engineCache = { key, error: e.message }; }
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
      await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: PLUGIN_ID, metadata });
      return true;
    } catch (e) {
      log.warn(`activity log entry not written: ${e.message}`, { message });
      return false;
    }
  }

  /** Write config.json from the settings; remembers when its content last changed (for "restart needed"). */
  async function writeConfig(settings, target) {
    const r = writeHardeningConfig(settings, { file: target.configPath, instanceRoot: target.instanceRoot, sandboxRootsEnv: target.sandboxRootsEnv });
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
    const target = requireTarget({ revalidate: true });
    const engine = engineFor();
    const startedAt = serverStartedAt(target);
    const status = await engine.status(startedAt === undefined ? {} : { serverStartedAt: startedAt });
    const prev = await ctx.state.get(SELFTEST_KEY).catch(() => null);
    const at = new Date().toISOString();
    if (status.restartNeeded) {
      await ctx.state.set(SELFTEST_KEY, { ...(prev ?? {}), at, trigger, waitingRestart: true, results: {} });
      return { ok: true, ran: false, reason: "Paperclip has not restarted since the last change; the self-test runs after the restart" };
    }
    const upstreamState = await ctx.state.get(UPSTREAM_KEY).catch(() => null);
    const upstream = Object.fromEntries((upstreamState?.protections ?? []).map((u) => [u.id, u.patches]));
    const r = await runSelfTestFn({ engine, status, upstream, instanceRoot: target.instanceRoot, userHome: target.userHome, env: { PAPERCLIP_HARDENING_CONFIG: target.configPath, ...(target.sandboxRootsEnv ? { PAPERCLIP_SANDBOX_WORKSPACE_ROOT: target.sandboxRootsEnv } : {}) } });
    const failed = Object.entries(r.results).filter(([, x]) => !x.ok).map(([id]) => id).sort();
    const signature = failed.join(",");
    let alertedSignature = prev?.alertedSignature ?? "";
    const title = (id) => getProtection(id)?.title ?? id;
    if (failed.length) {
      const lines = failed.map((id) => `- **${title(id)}** (${r.results[id].mode}): ${r.results[id].checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`).join("; ")}`);
      await logActivity(context, settings, `Security hardening self-test failed: ${failed.map(title).join(", ")}`, { trigger, failed, serverStartedAt: status.serverStartedAt,
        results: Object.fromEntries(failed.map((id) => [id, r.results[id].checks.filter((c) => !c.ok)])) });
      if (alertedSignature !== signature) {
        const a = await raiseAlertIssue({ ctx, settings, priority: "high", metadata: { source: "self-test", failed },
          title: `[Security hardening] Self-test failed: ${failed.map(title).join(", ")}`.slice(0, 240),
          description: `The self-test after ${trigger === "start" ? "Paperclip's start" : "a manual run"} (${at}) found switched-on protections that do not work as expected in the files Paperclip runs:\n\n${lines.join("\n")}\n\nOpen the Hardening page: the rows are red. Re-apply (Save) and restart, or check whether the Paperclip files were changed outside the plugin.` });
        if (a.ok) alertedSignature = signature;
      }
    } else if (alertedSignature) {
      await logActivity(context, settings, "Security hardening self-test passes again", { trigger });
      alertedSignature = "";
    }
    await ctx.state.set(SELFTEST_KEY, { ...r, trigger, serverStartedAt: status.serverStartedAt ?? null, failed, alertedSignature, waitingRestart: false });
    return { ok: failed.length === 0, ran: true, failed, results: r.results, at: r.at };
  }

  /** On start with an unknown target nothing is re-applied: log it and raise one alert per failure code. */
  async function alertTargetUnknown(err, settings) {
    log.error(`protections not re-applied on start: ${err.message}`);
    const prev = await ctx.state.get(TARGET_ALERT_KEY).catch(() => null);
    if (prev?.code === err.targetCode) return;
    const a = await raiseAlertIssue({ ctx, settings, priority: "high", metadata: { source: "target-unknown", code: err.targetCode },
      title: "[Security hardening] Cannot tell which Paperclip this plugin serves",
      description: `On start the plugin could not work out which Paperclip install it belongs to, so it changed nothing and will not re-apply the protections (for example after a Paperclip update):\n\n${err.message}\n\nOpen the Hardening page for the details. Apply or restore with the command-line tool (plugin/bin/hardening-engine.mjs, see its README) until this is resolved.` });
    if (a.ok) await ctx.state.set(TARGET_ALERT_KEY, { code: err.targetCode }).catch(() => {});
  }

  /**
   * Switched-on core protections that do not fit the Paperclip files (an update changed the code their patches change). They are skipped but
   * stay switched on; everything that still fits is applied by start(). A HIGH alert is raised (once per set of protections and Paperclip
   * version) and the Hardening page shows "update needs admin decision" on their rows. Exception (`held`): a protection that is IN the files
   * now (new patch files that do not fit the tree the engine built): rebuilding would drop it silently, which needs the owner's confirmation
   * like a switch-off, so then nothing is rebuilt (start() returns needsDecision).
   */
  async function reportUnfitting(plan, settings) {
    const items = plan.unfitting.map((c) => ({ id: c.id, title: c.title, risk: c.risk ?? null, reason: c.reason ?? null, held: c.held }));
    const held = items.some((i) => i.held);
    const signature = decisionSignature(plan);
    const prev = await ctx.state.get(UPDATE_DECISION_KEY).catch(() => null);
    const same = prev?.signature === signature;
    const names = items.map((i) => i.title).join(", ");
    const ids = items.map((i) => i.id);
    if (same && prev.accepted) {
      log.warn(`not fitting this Paperclip (accepted by an admin): ${names}`);
      return { held: false };
    }
    if (held) log.error(`protections NOT re-applied, nothing was rebuilt: ${names} no longer fit this Paperclip (${plan.paperclipVersion ?? "unknown version"}) and need an admin decision`);
    else log.error(`${names} no longer fit this Paperclip (${plan.paperclipVersion ?? "unknown version"}); skipped (still switched on), every other protection that fits is applied: update needs admin decision`);
    let alerted = same ? Boolean(prev.alerted) : false;
    if (!alerted) {
      const lines = items.map((i) => `- **${i.title}**: ${i.reason ?? "does not fit"}${i.risk ? ` If it is not in the files: ${i.risk}` : ""}`);
      const claudeNote = ids.includes("box-claude") && !ids.includes("only-boxed")
        ? " \"Only boxed agents run\" is applied without it, so Claude agents are refused (they are not registered as boxed) until a plugin release for this Paperclip brings \"Box Claude agents\" back."
        : "";
      const tail = held
        ? "Rebuilding the files would have removed them silently, so the plugin changed NOTHING: no protection was re-applied by this start. The files stay as they are. "
          + "Open the Hardening page (status \"update needs admin decision\"): install a plugin release that carries patches for this Paperclip, or Save to rebuild without the listed protections after confirming that you accept the risk."
        : "The plugin applied every other protection that still fits; the listed ones are skipped but stay switched on, so they come back as soon as a plugin release fits this Paperclip. Until then they are NOT in the files."
          + `${claudeNote} Open the Hardening page (status "update needs admin decision") and install a plugin release that carries patches for this Paperclip.`;
      const a = await raiseAlertIssue({ ctx, settings, priority: "high", metadata: { source: "update-needs-decision", protections: ids, paperclipVersion: plan.paperclipVersion ?? null },
        title: `[Security hardening] Paperclip update: ${names} no longer fit${items.length === 1 ? "s" : ""}, admin decision needed`.slice(0, 240),
        description: `On start the plugin found switched-on safety protections that no longer fit the Paperclip files (version ${plan.paperclipVersion ?? "unknown"}):\n\n${lines.join("\n")}\n\n${tail}` });
      alerted = a.ok;
    }
    await ctx.state.set(UPDATE_DECISION_KEY, { at: same && prev.at ? prev.at : new Date().toISOString(), paperclipVersion: plan.paperclipVersion ?? null, signature, alerted, held, accepted: false, protections: items }).catch(() => {});
    await logActivity(null, settings, `Security hardening: update needs admin decision (${names}); ${held ? "nothing was re-applied" : "the rest was re-applied"}`, { protections: ids, paperclipVersion: plan.paperclipVersion ?? null, held });
    return { held };
  }
  /** Heads-up (no alert): the change of a protection is now part of Paperclip, the protection counts as satisfied. Logged once per set and version. */
  async function noteUpstream(plan, settings) {
    if (!plan.nowUpstream.length) { await ctx.state.set(UPSTREAM_KEY, null).catch(() => {}); return; }
    const signature = `${plan.nowUpstream.map((u) => `${u.id}:${u.patches.join("+")}`).sort().join(",")}@${plan.paperclipVersion ?? "?"}`;
    const prev = await ctx.state.get(UPSTREAM_KEY).catch(() => null);
    if (prev?.signature === signature) return;
    await ctx.state.set(UPSTREAM_KEY, { signature, at: new Date().toISOString(), paperclipVersion: plan.paperclipVersion ?? null, protections: plan.nowUpstream }).catch(() => {});
    const names = plan.nowUpstream.map((u) => u.title).join(", ");
    log.info(`now part of Paperclip, no longer needed: ${names}`);
    await logActivity(null, settings, `Security hardening: now part of Paperclip, no longer needed (${names})`, { protections: plan.nowUpstream, paperclipVersion: plan.paperclipVersion ?? null });
  }
  const decisionSignature = (plan) => `${plan.unfitting.map((i) => i.id).sort().join(",")}@${plan.paperclipVersion ?? "?"}`;
  /** Local_trusted: every caller without a token is the board (a boxed agent included): one HIGH alert while the instance runs that way. */
  async function checkDeploymentMode(target, settings) {
    if (target.deploymentMode !== "local_trusted") { await ctx.state.set(LOCAL_TRUSTED_KEY, null).catch(() => {}); return; }
    const prev = await ctx.state.get(LOCAL_TRUSTED_KEY).catch(() => null);
    if (prev?.alerted) return;
    log.error(LOCAL_TRUSTED_TEXT);
    const a = await raiseAlertIssue({ ctx, settings, priority: "high", metadata: { source: "local-trusted" },
      title: "[Security hardening] Paperclip runs in local_trusted mode: agents can act as the board",
      description: `${LOCAL_TRUSTED_TEXT}\n\nSwitch the instance to authenticated mode (deployment mode "authenticated" in its config file or PAPERCLIP_DEPLOYMENT_MODE) and restart Paperclip. The protections of this plugin that decide by "who is calling" (board-only changes, the Test probe) cannot hold against a caller that Paperclip already treats as the board.` });
    if (a.ok) await ctx.state.set(LOCAL_TRUSTED_KEY, { alerted: true }).catch(() => {});
  }
  const clearDecision = () => ctx.state.set(UPDATE_DECISION_KEY, null).catch(() => {});

  const api = {
    assertAdmin,
    loadSettings,
    selfTestNow,
    /** The Paperclip this worker serves (throws TargetUnknownError); other services read their paths from it. */
    target: () => requireTarget(),
    setHostStatus(fn) { hostStatusFn = fn; },
    setItsec(service) { itsec = service; },

    /** Admin action "runSelfTest" (the page's button). */
    runSelfTest(params = {}, context) {
      return exclusive(async () => {
        await assertAdmin(context);
        return selfTestNow({ trigger: "manual", context });
      });
    },

    /** After the worker started (= Paperclip (re)started): the automatic self-test. */
    selfTestAfterStart() {
      return exclusive(async () => {
        try { return await selfTestNow({ trigger: "start" }); }
        catch (e) {
          if (!(e instanceof TargetUnknownError)) throw e;
          return { ok: true, ran: false, reason: e.message }; // start() already logged and alerted
        }
      });
    },

    async getSettings() {
      const settings = await loadSettings();
      let enabled = null;
      let target = null;
      try { target = requireTarget(); enabled = (await engineFor().status()).enabled; } catch { enabled = null; }
      return { settings, enabled, configPath: target?.configPath ?? null, target: target ? { ok: true, ...summarizeTarget(target) } : null };
    },

    async getStatus() {
      let target;
      let engine;
      try { target = requireTarget(); engine = engineFor(); }
      catch (e) {
        return { available: false, reason: e.message, target: target ? { ok: true, ...summarizeTarget(target) } : { ok: false, code: e.targetCode ?? null, reason: e.message },
          protections: PROTECTIONS.map((p) => rowFor(p, null, null, null, null)), restart: null, configPath: target?.configPath ?? null };
      }
      const startedAt = serverStartedAt(target);
      const status = await engine.status(startedAt === undefined ? {} : { serverStartedAt: startedAt });
      const unavailable = await availability(engine, status).catch(() => ({}));
      const byId = Object.fromEntries(status.protections.map((p) => [p.id, p]));
      const st = await ctx.state.get(SELFTEST_KEY).catch(() => null);
      const withFiles = Object.fromEntries(engine.protections().map((p) => [p.id, p]));
      const selfTests = {};
      for (const [id, res] of Object.entries(st?.results ?? {})) {
        if (withFiles[id] && res?.filesKey === filesKey(withFiles[id], status.files)) selfTests[id] = { ...res, at: st.at, trigger: st.trigger };
      }
      const decision = await ctx.state.get(UPDATE_DECISION_KEY).catch(() => null);
      const upstream = await ctx.state.get(UPSTREAM_KEY).catch(() => null);
      const hosts = hostStatusFn ? await hostStatusFn().catch((e) => { log.warn(`host install status unavailable: ${e.message}`); return null; }) : null;
      const info = engine.restartInfo();
      const started = status.serverStartedAt;
      const cfgState = await ctx.state.get(CONFIG_STATE_KEY).catch(() => null);
      const configPending = Boolean(cfgState?.pending) && READS_CONFIG.some((id) => ["applied", "pending-restart"].includes(byId[id]?.status))
        && (started && cfgState.at ? Date.parse(cfgState.at) > Date.parse(started) : true);
      return {
        available: true,
        target: { ok: true, ...summarizeTarget(target) },
        tree: status.tree,
        paperclipVersion: status.paperclipVersion,
        enabled: status.enabled,
        protections: PROTECTIONS.map((p) => rowFor(p, byId[p.id], unavailable[p.id] ?? null, selfTests[p.id] ?? null, hosts, decision?.protections?.find((d) => d.id === p.id) ?? null, upstream?.protections?.find((d) => d.id === p.id) ?? null)),
        nowUpstream: upstream?.protections?.length ? { at: upstream.at ?? null, paperclipVersion: upstream.paperclipVersion ?? null, protections: upstream.protections } : null,
        deploymentMode: target.deploymentMode ?? null,
        localTrusted: target.deploymentMode === "local_trusted" ? LOCAL_TRUSTED_TEXT : null,
        updateDecision: decision?.protections?.length ? { at: decision.at ?? null, paperclipVersion: decision.paperclipVersion ?? null, held: Boolean(decision.held), protections: decision.protections } : null,
        selfTest: st ? { at: st.at ?? null, trigger: st.trigger ?? null, waitingRestart: Boolean(st.waitingRestart), failed: st.failed ?? [] } : null,
        watchdog: hosts?.watchdog ?? null,
        hermes: hosts?.hermes ?? null,
        files: status.files.map((f) => ({ rel: f.rel, state: f.state })),
        restart: {
          needed: status.restartNeeded || configPending,
          settingsChanged: configPending,
          why: status.restartNeeded || configPending ? restartWhy({ filesChanged: status.restartNeeded, settingsChanged: configPending }) : null,
          manualText: info.canRestart ? null : manualRestartText(info.reason),
          canRestart: info.canRestart,
          commandText: info.commandText,
          reason: info.reason ?? null,
          startedAt: started,
        },
        configPath: target.configPath,
      };
    },

    async planChange(params = {}, context) {
      if (context?.actor?.type === "agent") throw new NotAllowedError("agents cannot plan protection changes");
      const engine = engineFor();
      const current = (await engine.status()).enabled;
      const req = resolveRequest(current, parseEnabled(params));
      const plan = await engine.plan(req.enabled, { repair: params.repair === true, adoptOrig: params.adoptOrig === true });
      return summarizePlan(plan, req.switchedOff);
    },

    applyChange(params = {}, context) {
      return exclusive(async () => {
        const actor = await assertAdmin(context);
        const settings = await loadSettings();
        requireTarget({ revalidate: true });
        const engine = engineFor();
        const before = (await engine.status()).enabled;
        const req = resolveRequest(before, parseEnabled(params));
        const plan = await engine.plan(req.enabled, { repair: params.repair === true, adoptOrig: params.adoptOrig === true });
        requireTarget({ revalidate: true }); // still the same Paperclip between plan and write
        const result = await engine.apply(plan, { confirmCoreOff: params.confirmCoreOff === true });
        availabilityCache = null;
        const summary = summarizePlan(plan, req.switchedOff);
        if (!result.ok) return { ok: false, error: result.error, plan: summary };
        // Nothing left that does not fit: the alert is over. Dropping one that is in the files needed the confirmation: that is the decision,
        // remembered for this set and Paperclip version so that the next start does not alert again.
        if (!plan.unfitting.length) await clearDecision();
        else if (params.confirmCoreOff === true && plan.confirmationNeeded.length) await ctx.state.set(UPDATE_DECISION_KEY, { at: new Date().toISOString(), paperclipVersion: plan.paperclipVersion ?? null, signature: decisionSignature(plan), alerted: true, held: false, accepted: true, protections: [] }).catch(() => {});
        const after = (await engine.status()).enabled;
        const changedSet = before.join(",") !== after.join(",");
        if (result.changed.length || changedSet) {
          const turnedOn = after.filter((id) => !before.includes(id));
          const turnedOff = before.filter((id) => !after.includes(id));
          await logActivity(context, settings,
            `Security hardening changed: ${[...turnedOn.map((id) => `+${id}`), ...turnedOff.map((id) => `-${id}`)].join(" ") || "files rebuilt"}${result.restartNeeded ? " (restart needed)" : ""}`,
            { userId: actor.userId, enabled: after, turnedOn, turnedOff, changedFiles: result.changed, unavailable: Object.keys(result.unavailable ?? {}), confirmCoreOff: params.confirmCoreOff === true });
        }
        return { ok: true, changed: result.changed, applied: result.applied, unavailable: result.unavailable, restartNeeded: result.restartNeeded, plan: summary };
      });
    },

    restart(params = {}, context) {
      return exclusive(async () => {
        const actor = await assertAdmin(context);
        const settings = await loadSettings();
        requireTarget({ revalidate: true });
        const engine = engineFor();
        const info = engine.restartInfo();
        if (!info.canRestart)
          return { ok: false, manual: true, message: manualRestartText(info.reason ?? "it does not run as a systemd user unit here") };
        // Logged first: the restart stops this worker together with Paperclip.
        await logActivity(context, settings, `Security hardening: Paperclip restart requested (${info.commandText})`, { userId: actor.userId });
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
        requireTarget({ revalidate: true });
        const engine = engineFor();
        const r = await engine.restoreAll({ force: params.force === true });
        availabilityCache = null;
        if (r.ok) await logActivity(context, settings, `Security hardening: all protections switched off, original Paperclip files restored${r.restartNeeded ? " (restart needed)" : ""}`,
          { userId: actor.userId, restored: r.restored, skipped: r.skipped });
        return r;
      });
    },

    saveSettings(params = {}, context) {
      return exclusive(async () => {
        const actor = await assertAdmin(context);
        const target = requireTarget({ revalidate: true });
        const prev = await loadSettings();
        const { settings: parsed, errors } = normalizeSettings(params.settings);
        // The ITSec keys change only when the request carries them: the general site form does not send them, so it can
        // neither clear nor overwrite the host company marking.
        const given = (k) => params.settings && typeof params.settings === "object" && k in params.settings;
        const settings = { ...parsed, ...Object.fromEntries(ITSEC_SETTING_KEYS.filter((k) => !given(k)).map((k) => [k, prev[k]])) };
        const actorCompany = actor.companyId ?? context?.companyId ?? null;
        if (itsec) errors.push(...(await itsec.validateChange(prev, settings, actorCompany)));
        else if (ITSEC_SETTING_KEYS.some((k) => settings[k] !== prev[k])) errors.push("the ITSec agent service is not running");
        if (errors.length) return { ok: false, errors };
        let r;
        try { r = await writeConfig(settings, target); } // refused: nothing is stored either, so the page never shows settings the server does not use
        catch (e) { if (e instanceof HardeningConfigRefusal) return { ok: false, errors: [`the settings file was not written: ${e.message}`] }; throw e; }
        await ctx.state.set(SETTINGS_KEY, settings);
        if (r.changed) await logActivity(context, settings, "Security hardening: site settings changed", { userId: actor.userId, configPath: r.file, config: r.config });
        let itsecResult = null;
        if (itsec && ITSEC_SETTING_KEYS.some((k) => settings[k] !== prev[k])) {
          await logActivity(context, settings, settings.itsecHostCompanyId !== prev.itsecHostCompanyId
            ? (settings.itsecHostCompanyId ? "Security hardening: host company for the ITSec agent set" : "Security hardening: host company for the ITSec agent cleared")
            : "Security hardening: ITSec settings changed", { userId: actor.userId, hostCompanyId: settings.itsecHostCompanyId || null });
          itsecResult = await itsec.applyChange(prev, settings, actorCompany);
        }
        return { ok: true, settings, configPath: r.file, configChanged: r.changed, itsec: itsecResult };
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
        let target;
        try { target = requireTarget({ revalidate: true }); }
        catch (e) {
          if (!(e instanceof TargetUnknownError)) throw e;
          await alertTargetUnknown(e, settings);
          return { ok: false, error: e.message, code: e.targetCode, config: null };
        }
        await ctx.state.set(TARGET_ALERT_KEY, { code: null }).catch(() => {});
        await checkDeploymentMode(target, settings);
        // Only once an admin saved settings: never replace a settings file written by hand before the plugin was set up.
        const saved = await ctx.state.get(SETTINGS_KEY).catch(() => null);
        const cfg = saved === null ? null
          : await writeConfig(settings, target).catch((e) => { log.error(`cannot write the hardening settings file: ${e.message}`); return null; });
        let engine;
        try { engine = engineFor(); } catch (e) { log.warn(e.message); return { ok: false, error: e.message, config: cfg }; }
        const enabled = (await engine.status()).enabled;
        if (!enabled.length) return { ok: true, applied: false, reason: "nothing switched on", config: cfg };
        const plan = await engine.replan();
        const unfitting = plan.unfitting.map((u) => u.id);
        await noteUpstream(plan, settings);
        if (!unfitting.length) await clearDecision();
        else {
          const { held } = await reportUnfitting(plan, settings);
          if (held || plan.confirmationNeeded.length) {
            return { ok: false, applied: false, needsDecision: true, protections: unfitting, config: cfg,
              error: `${plan.unfitting.map((u) => u.title).join(", ")} no longer fit${unfitting.length === 1 ? "s" : ""} this Paperclip; nothing was rebuilt` };
          }
        }
        if (!plan.changes) return { ok: true, applied: false, reason: "files already match", unfitting, config: cfg };
        const result = await engine.apply(plan);
        availabilityCache = null;
        if (!result.ok) { log.error(`re-applying the protections failed: ${result.error}`); return { ok: false, error: result.error, config: cfg }; }
        const refreshed = plan.files.filter((f) => f.pristineSource === "refreshed").map((f) => f.rel);
        await logActivity(null, settings, `Security hardening re-applied after start${refreshed.length ? " (Paperclip files changed, e.g. an update)" : ""}; restart Paperclip to activate`,
          { changedFiles: result.changed, refreshedOriginals: refreshed, unavailable: Object.keys(result.unavailable ?? {}) });
        return { ok: true, applied: true, changed: result.changed, unavailable: result.unavailable, unfitting, config: cfg };
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

function rowFor(p, st, unavailableReason, selfTest = null, hosts = null, decision = null, upstream = null) {
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
  if (decision && !placeholder) {
    // This core protection no longer fits (see reportUnfitting): not "off", not "unavailable".
    status = "needs-decision";
    reason = decision.held
      ? `A Paperclip update changed the code this protection patches (${decision.reason ?? "it does not fit"}). Nothing was rebuilt; Save asks you to confirm dropping it.`
      : `A Paperclip update changed the code this protection patches (${decision.reason ?? "it does not fit"}). It is skipped and stays switched on; the protections that fit were applied. A plugin release that fits this Paperclip brings it back on the next start.`;
  }
  if (upstream && !placeholder && !decision && ["applied", "pending-restart"].includes(status))
    reason = `Now part of Paperclip (${upstream.patches.join(", ")}): no longer needed.`;
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
