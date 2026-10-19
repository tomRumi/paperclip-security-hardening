import { definePlugin, runWorker } from "@paperclipai/plugin-sdk";
import { checkAgents, signature, listAgents, listCompanies } from "./logic.js";
import { createHardening } from "./hardening.js";
import { createBoxes, resolveTarget } from "./boxes.js";
import { createCaps } from "./caps.js";
import { createHostInstalls } from "./hostinstall.js";
import { createAlertRecheck } from "./recheck.js";

/** Action keys the Hardening page uses. Writes (applyChange, restart, restoreAll, saveSettings, runSelfTest,
 *  hostInstallCommand, which creates a watchdog enrolment code) are admin-only; see hardening.js for how that is
 *  enforced. */
export const ACTIONS = ["getStatus", "getSettings", "planChange", "applyChange", "restart", "restoreAll", "saveSettings", "runSelfTest", "hostInstallCommand"];
/** Action keys the Agent boxes page uses. Reads are users only (another company: admin); writes are admin-only (see
 *  boxes.js resolveTarget, which reuses hardening.assertAdmin). Reads are actions, not data keys, because only
 *  actions carry the caller's identity. */
export const BOX_ACTIONS = ["listCompanies", "agentBoxes", "takeOverBox", "saveBox", "saveCompanyCaps", "saveAgentCap", "saveCapsInstall"];

/** The services of the running worker (onWebhook needs them; it is not registered through ctx). */
let services = null;

/** Exported for tests with a fake ctx; `hardening`, `boxes`, `caps`, `hosts` and `recheck` let tests pass their own services. */
export function register(ctx, { hardening, boxes, caps, hosts, recheck } = {}) {
  const h = hardening ?? createHardening({ ctx });
  const assertAdmin = (context) => h.assertAdmin(context);
  const w = hosts ?? createHostInstalls({ ctx, assertAdmin, loadSettings: () => h.loadSettings() });
  h.setHostStatus?.(async () => ({ watchdog: await w.watchdogStatus(), hermes: await w.hermesStatus() }));
  services = { h, w };
  const c = caps ?? createCaps({ ctx, assertAdmin });
  // No applyBox: the plugin SDK has no capability to change an agent's adapterConfig (see boxes.js).
  const b = boxes ?? createBoxes({ ctx, assertAdmin, loadSettings: () => h.loadSettings(), capsView: (companyId, agents) => c.view(companyId, agents) });
  // The compliance check uses the install-wide Hermes wrapper path from the hardening settings.
  const cfg = async (companyId) => {
    const company = (await ctx.config.get(companyId)) ?? {};
    const site = await h.loadSettings().catch(() => null);
    return site?.hermesWrapperPath ? { ...company, hermesWrapperPath: site.hermesWrapperPath } : company;
  };

  ctx.data.register("compliance", async ({ companyId }) => {
    const results = checkAgents(await listAgents(ctx, String(companyId)), await cfg(companyId));
    return { checkedAt: new Date().toISOString(), total: results.length, nonCompliant: results.filter((r) => !r.compliant).length, results };
  });

  ctx.data.register("hardening-status", () => h.getStatus());
  ctx.data.register("hardening-settings", () => h.getSettings());
  ctx.actions.register("getStatus", () => h.getStatus());
  ctx.actions.register("getSettings", () => h.getSettings());
  ctx.actions.register("planChange", (params, context) => h.planChange(params, context));
  ctx.actions.register("applyChange", (params, context) => h.applyChange(params, context));
  ctx.actions.register("restart", (params, context) => h.restart(params, context));
  ctx.actions.register("restoreAll", (params, context) => h.restoreAll(params, context));
  ctx.actions.register("saveSettings", (params, context) => h.saveSettings(params, context));
  ctx.actions.register("runSelfTest", (params, context) => h.runSelfTest(params, context));
  ctx.actions.register("hostInstallCommand", (params, context) => w.command(params, context));

  ctx.actions.register("listCompanies", async (params, context) => {
    const { companyId } = await resolveTarget(assertAdmin, {}, context);
    let admin = false;
    try { await assertAdmin(context); admin = true; } catch { admin = false; }
    const all = admin ? await listCompanies(ctx) : [];
    const list = admin ? all : [{ id: companyId, name: null }];
    return { companies: list.map((x) => ({ id: String(x.id), name: x.name ?? null })), current: companyId, admin };
  });
  ctx.actions.register("agentBoxes", (params, context) => b.view(params, context));
  ctx.actions.register("takeOverBox", (params, context) => b.takeOver(params, context));
  ctx.actions.register("saveBox", (params, context) => b.saveBox(params, context));
  ctx.actions.register("saveCompanyCaps", (params, context) => c.saveCompanyCaps(params, context));
  ctx.actions.register("saveAgentCap", (params, context) => c.saveAgentCap(params, context));
  ctx.actions.register("saveCapsInstall", (params, context) => c.saveInstall(params, context));

  ctx.jobs.register("daily-token-caps", async () => {
    const r = await c.runJob();
    if (r?.errors?.length) ctx.logger?.warn?.(`daily token caps: ${r.errors.length} error(s)`, { errors: r.errors });
  });

  ctx.jobs.register("watchdog-heartbeat", async () => { await w.checkHeartbeat(); });

  // Alert tamper re-check (src/recheck.js): close events of the plugin's alert issues carry the actor; the job
  // re-raises an alert that someone other than an alert owner closed, cancelled, deleted or hid.
  const r = recheck ?? createAlertRecheck({ ctx });
  ctx.events?.on?.("issue.updated", (event) => r.recordEvent(event));
  ctx.jobs.register("alert-recheck", async () => {
    const res = await r.runJob();
    const raised = res.filter((x) => x.result === "re-raised").length;
    if (raised) ctx.logger?.warn?.(`alert re-check: ${raised} tampered alert(s) re-raised`, { results: res });
  });

  ctx.jobs.register("verify-sandbox-config", async () => {
    for (const company of await listCompanies(ctx)) {
      const results = checkAgents(await listAgents(ctx, company.id), await cfg(company.id));
      const sig = signature(results);
      const key = { scopeKind: "company", scopeId: String(company.id), stateKey: "last-signature" };
      if ((await ctx.state.get(key)) === sig) continue;
      await ctx.state.set(key, sig);
      const bad = results.filter((r) => !r.compliant);
      await ctx.activity.log({
        companyId: String(company.id),
        message: bad.length ? `Sandbox hardening drift: ${bad.length} agent(s) not compliant` : "Sandbox hardening: all agents compliant again",
        entityType: "plugin", entityId: "paperclip-sandbox-hardening",
        metadata: { nonCompliant: bad.map((r) => ({ id: r.id, name: r.name, findings: r.findings })) },
      });
    }
  });
  return h;
}

const plugin = definePlugin({
  async setup(ctx) {
    const h = register(ctx);
    // Not awaited: rebuilding can take a few seconds and must not hold up the worker's start. The worker starts with
    // Paperclip, so the self-test that follows is the "after restart" check (skipped while a restart is pending).
    h.start().then(
      (r) => { if (r.applied) ctx.logger.info("protections re-applied on start; Paperclip needs a restart", { changed: r.changed }); },
      (e) => ctx.logger.error(`hardening start failed: ${e.message}`),
    ).then(() => h.selfTestAfterStart()).then(
      (r) => { if (r.ran && !r.ok) ctx.logger.error(`self-test failed: ${r.failed.join(", ")}`); },
      (e) => ctx.logger.error(`self-test could not run: ${e.message}`),
    );
  },
  // POST /api/plugins/paperclip-sandbox-hardening/webhooks/watchdog (no Paperclip auth; every message is signed with
  // the watchdog's enrolled key, see hostinstall.js). Throwing makes the host answer 502 and record a failed delivery.
  async onWebhook(input) {
    if (!services) throw new Error("plugin not set up");
    await services.w.handleWebhook(input);
  },
  async onHealth() { return { status: "ok" }; },
  // Company config (adminUserIds, compliance exceptions) is read on demand; nothing to reload, and no worker restart.
  async onConfigChanged() {},
});
export default plugin;
runWorker(plugin, import.meta.url);
