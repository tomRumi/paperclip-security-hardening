// One alert = an activity-log entry plus, when an alert company is configured and the SDK offers issue creation
// (capability issues.create), an issue created by the plugin itself in the alert company/project. The issue is not
// assigned to anyone, so it wakes no agent. Every created alert issue is remembered (ALERT_LOG_KEY) for the tamper
// re-check in src/recheck.js: only the alert owners may close it.
import { PLUGIN_ID } from "./manifest.js";

export const PLUGIN_ENTITY = PLUGIN_ID;

/** {issues: {issueId: {companyId, projectId, identifier, title, description, priority, source, raisedAt, reraised}}} */
export const ALERT_LOG_KEY = Object.freeze({ scopeKind: "instance", stateKey: "alert-log" });
/** Newest alerts kept for the re-check (older ones are dropped first, pending ones last); the stored text is capped. */
export const MAX_TRACKED_ALERTS = 200;
const MAX_STORED_DESCRIPTION = 8000;

let alertListener = null;
/**
 * One listener (the worker sets it) is told about every alert issue that was created: {companyId, issueId, priority,
 * source}. The ITSec agent's triage nudge hangs on it (src/itsec.js). The listener never delays or fails an alert.
 */
export function setAlertListener(fn) { alertListener = typeof fn === "function" ? fn : null; }

/** Remember a created alert issue for the re-check. Never throws (a failed write only costs the re-check). */
export async function trackAlert(ctx, issueId, entry) {
  try {
    const log = (await ctx.state.get(ALERT_LOG_KEY)) ?? {};
    const issues = { ...(log.issues ?? {}), [issueId]: { ...entry, description: String(entry.description ?? "").slice(0, MAX_STORED_DESCRIPTION) } };
    // Alerts with a pending verification or a failed re-raise (src/recheck.js) are evicted last, whatever their age.
    const pending = (x) => (x.verifyFailures || x.reraiseFailed ? 1 : 0);
    const keep = Object.entries(issues).sort(([, a], [, b]) => pending(b) - pending(a) || String(b.raisedAt).localeCompare(String(a.raisedAt))).slice(0, MAX_TRACKED_ALERTS);
    await ctx.state.set(ALERT_LOG_KEY, { ...log, issues: Object.fromEntries(keep) });
    return true;
  } catch (e) {
    ctx.logger?.warn?.(`alert issue not remembered for the re-check: ${e.message}`);
    return false;
  }
}

/**
 * @param {object} [o.recheck]  {reraised} for a re-raised alert (src/recheck.js); default 0
 * @returns {Promise<{ok: boolean, issue?: {issueId, identifier}, reason?: string}>}  ok false: nothing was raised
 *          (no alert company, or the issue could not be created; the activity entry is still written when possible)
 */
export async function raiseAlertIssue({ ctx, settings, title, description, priority = "high", metadata = {}, recheck = {}, now = Date.now }) {
  const log = ctx.logger ?? { info() {}, warn() {} };
  const companyId = settings?.alertCompanyId || null;
  if (!companyId) { log.warn(`alert not raised (no alert company configured): ${title}`); return { ok: false, reason: "no alert company configured in the Security hardening settings" }; }
  const activity = async (message, extra) => {
    try { await ctx.activity.log({ companyId, message, entityType: "plugin", entityId: PLUGIN_ENTITY, metadata: { ...metadata, ...extra } }); }
    catch (e) { log.warn(`activity log entry not written: ${e.message}`, { message }); }
  };
  let issue = { issueId: null, identifier: null };
  if (typeof ctx.issues?.create === "function") {
    const projectId = settings.alertProjectId || null;
    try {
      // originKind is left to the host: it defaults to "plugin:<this plugin's id>", which is how the alert issues are found again.
      const created = await ctx.issues.create({ companyId, ...(projectId ? { projectId } : {}), title, description, status: "todo", priority });
      issue = { issueId: created?.id ?? null, identifier: created?.identifier ?? null };
    } catch (e) {
      await activity(`Security hardening alert (issue not created: ${e.message}): ${title}`, { title });
      return { ok: false, reason: `issue not created: ${e.message}` };
    }
    if (issue.issueId) {
      await trackAlert(ctx, String(issue.issueId), { companyId, projectId, identifier: issue.identifier, title, description, priority,
        source: metadata.source ?? null, raisedAt: new Date(now()).toISOString(), reraised: Number(recheck.reraised) || 0 });
      if (alertListener) {
        // Fire and forget: the listener may queue behind a long operation and must never delay or fail the alert.
        const warn = (e) => log.warn(`alert listener failed: ${e?.message ?? e}`);
        try { Promise.resolve(alertListener({ companyId, issueId: String(issue.issueId), priority, source: metadata.source ?? null })).catch(warn); }
        catch (e) { warn(e); }
      }
    }
  }
  await activity(`Security hardening alert: ${title}`, { title, issue });
  return { ok: true, issue };
}
