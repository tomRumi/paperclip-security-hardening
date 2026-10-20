// Plain ESM (no build step); `react` and `@paperclipai/plugin-sdk/ui` are host-provided externals.
// The Hardening page: one row per protection with an on/off switch, Save (shows the plan, then applies), restart,
// restore originals, and the install-wide site settings. Writes are checked again in the worker (admin only).
import React from "react";
import { usePluginData, usePluginAction, StatusBadge, DataTable } from "@paperclipai/plugin-sdk/ui";
const h = React.createElement;
const { useState, useEffect } = React;

const STATUS = {
  applied: { label: "applied", tone: "ok" },
  "pending-restart": { label: "pending restart", tone: "pending" },
  unavailable: { label: "unavailable on this install", tone: "warning" },
  drifted: { label: "drifted (files changed outside the plugin)", tone: "error" },
  "selftest-failed": { label: "self-test failed", tone: "error" },
  waiting: { label: "waiting for the watchdog to report in", tone: "pending" },
  silent: { label: "no heartbeat for over 30 minutes", tone: "error" },
  unsafe: { label: "unsafe (not root-owned, or writable by others)", tone: "error" },
  differs: { label: "differs from the released wrapper", tone: "warning" },
  off: { label: "off", tone: "info" },
  on: { label: "on", tone: "ok" },
  unknown: { label: "unknown", tone: "info" },
  placeholder: { label: "coming in a later step", tone: "info" },
};
const box = { border: "1px solid rgba(127,127,127,0.3)", borderRadius: 8, padding: 12 };
const muted = { opacity: 0.7, fontSize: "0.9em" };
const listText = (v) => (Array.isArray(v) ? v.join("\n") : "");
const errText = (e) => (e && e.message) || String(e);

function Switch({ checked, disabled, onChange, label }) {
  return h("label", { style: { display: "inline-flex", alignItems: "center", gap: 6, cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.5 : 1 } },
    h("input", { type: "checkbox", role: "switch", "aria-label": label, checked: Boolean(checked), disabled, onChange: (e) => onChange(e.target.checked) }),
    checked ? "on" : "off");
}

function selfTestText(t) {
  if (!t) return "self-test: not run since the last change";
  return `self-test ${t.ok ? "passed" : "FAILED"} (${t.mode}${t.mode === "functional" ? ", plus file check" : ""}) at ${t.at}`;
}

/** The one-line install / removal command for a host-installed part, and "waiting for it to report in". */
function HostInstallModal({ open, row, onClose, refresh }) {
  useEffect(() => {
    if (!open) return undefined;
    const t = setInterval(() => refresh(), 5000);
    return () => clearInterval(t);
  }, [open]);
  if (!open) return null;
  const r = open.result;
  const install = open.mode === "install";
  const done = install ? row?.status === "on" : row?.status === "off";
  const what = open.kind === "watchdog" ? "the watchdog" : "the Hermes wrapper";
  return h("div", { role: "dialog", "aria-label": `${install ? "Install" : "Remove"} ${what}`, style: { position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 } },
    h("div", { style: { ...box, background: "var(--background, #fff)", color: "inherit", maxWidth: 860, width: "calc(100% - 32px)", display: "grid", gap: 10 } },
      h("h3", { style: { margin: 0 } }, `${install ? "Install" : "Remove"} ${what}`),
      !r ? h("p", null, "Preparing the command...")
        : !r.ok ? h(StatusBadge, { label: r.error, status: "warning" })
          : h("div", { style: { display: "grid", gap: 8 } },
            h("p", { style: { margin: 0 } }, r.explanation),
            h("pre", { style: { fontFamily: "monospace", whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0, padding: 8, border: "1px solid rgba(127,127,127,0.3)", borderRadius: 6 } }, r.command),
            h("p", { style: muted }, `Installer ${r.url}, sha256 ${r.sha256} (release ${r.version ?? "?"}).${r.expiresAt ? ` The one-time code expires at ${r.expiresAt}; open this again for a new one.` : ""}`)),
      r?.ok ? h(StatusBadge, done
        ? { label: install ? (open.kind === "watchdog" ? "The watchdog reported in." : "The wrapper is installed.") : "Removed.", status: "ok" }
        : { label: install ? (open.kind === "watchdog" ? "Waiting for the watchdog to report in..." : "Waiting for the wrapper to appear...") : "Waiting for the removal...", status: "pending" }) : null,
      h("div", null, h("button", { type: "button", onClick: onClose }, "Close"))));
}

function PlanView({ plan, confirmed, setConfirmed }) {
  const items = (list, render) => h("ul", { style: { margin: "4px 0 8px 18px" } }, list.map((x) => h("li", { key: x.id }, render(x))));
  const changing = plan.protections.filter((p) => p.action === "will-apply" || p.action === "will-remove");
  return h("div", { style: { ...box, display: "grid", gap: 6 } },
    h("strong", null, "This save will:"),
    changing.length ? items(changing, (p) => `${p.action === "will-apply" ? "switch on" : "switch off"}: ${p.title}`) : h("p", null, "change no protection."),
    plan.added.length ? h("div", null, "Also switched on, because others need them:", items(plan.added, (a) => `${a.title} (needed by ${a.neededBy.join(", ")})`)) : null,
    plan.switchedOffDependents.length ? h("div", null, "Also switched off, because they need what you switched off:", items(plan.switchedOffDependents, (d) => `${d.title} (needs ${d.because.join(", ")})`)) : null,
    plan.keptOn.length ? h("div", null, "Kept on, still needed:", items(plan.keptOn, (a) => `${a.title} (needed by ${a.neededBy.join(", ")})`)) : null,
    Object.keys(plan.unavailable).length ? h("div", null, "Unavailable on this install (left off):", items(Object.entries(plan.unavailable).map(([id, reason]) => ({ id, reason })), (u) => `${u.id}: ${u.reason}`)) : null,
    plan.confirmationNeeded.length ? h("div", { style: { ...box, borderColor: "rgba(220,60,60,0.6)" } },
      h("strong", null, "You are switching off safety protections:"),
      items(plan.confirmationNeeded, (c) => h("span", null, h("b", null, c.title), ": ", c.risk)),
      h("label", null, h("input", { type: "checkbox", checked: confirmed, onChange: (e) => setConfirmed(e.target.checked) }), " I understand the risk and want to switch them off.")) : null,
    h("p", { style: muted }, plan.restartNeededAfterApply ? `${plan.changes} Paperclip file(s) will be rebuilt; one restart activates the change.` : "No Paperclip file changes."));
}

function SettingsForm({ settings, userId, onSave, busy }) {
  const [form, setForm] = useState(() => (settings ? { ...settings } : null));
  useEffect(() => { if (settings) setForm({ ...settings }); }, [settings]);
  if (!form) return h("p", null, "Loading settings...");
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
  const area = (k, label, hint) => h("label", { style: { display: "grid", gap: 4 } }, h("span", null, label), h("span", { style: muted }, hint),
    h("textarea", { rows: 3, value: Array.isArray(form[k]) ? listText(form[k]) : form[k], onChange: set(k), style: { fontFamily: "monospace" } }));
  const input = (k, label, hint) => h("label", { style: { display: "grid", gap: 4 } }, h("span", null, label), h("span", { style: muted }, hint),
    h("input", { type: "text", value: form[k] ?? "", onChange: set(k), style: { fontFamily: "monospace" } }));
  return h("div", { style: { display: "grid", gap: 10 } },
    h("p", { style: muted }, "One entry per line. An empty field uses Paperclip's secure default. New values reach Paperclip after a restart; existing agents are not changed."),
    area("baseAllowlist", "Base allowlist for new agents", "host or host:port. Default: the model API host only (api.anthropic.com); the Paperclip API is always reachable."),
    area("extraReadOnlyPaths", "Extra read-only paths for new agents", "Absolute paths. Default: none."),
    area("workspaceRoots", "Workspace roots", "Boxed runs may only use workspaces inside these. Default: Paperclip's own workspaces and projects folders."),
    input("hermesWrapperPath", "Hermes wrapper path", "Command new Hermes agents run. Default: /usr/local/bin/hermes-sandbox."),
    area("hermesAllowlist", "Hermes allowlist", "Default: the model API host only (openrouter.ai). Add the Paperclip API host:port if Hermes agents call it."),
    area("hermesReadOnlyPaths", "Hermes read-only paths", "Replaces the wrapper's default (the Hermes install), so list the Hermes install folders too. Default: the wrapper's own."),
    input("alertCompanyId", "Alert company id", "Company that receives alert issues (watchdog alerts, failed self-test, silent watchdog). Empty: activity log only."),
    input("alertProjectId", "Alert project id", "Project for alert issues (optional)."),
    input("paperclipUrl", "Paperclip URL for the watchdog", "http(s)://host:port as the host reaches Paperclip; used in the watchdog's install command. Default: http://127.0.0.1:3100."),
    h("div", null, h("button", { type: "button", disabled: busy, onClick: () => onSave(form) }, "Save settings")),
    h("p", { style: muted }, `Your user id: ${userId ?? "unknown"} (an instance admin adds it to "Users who may change protections" in this plugin's settings).`));
}

function Compliance({ companyId }) {
  const comp = usePluginData("compliance", { companyId });
  if (!companyId) return null;
  if (comp.loading) return h("p", null, "Loading...");
  if (comp.error) return h("p", null, "Error: " + errText(comp.error));
  const d = comp.data;
  return h("div", null,
    h(StatusBadge, { label: d.nonCompliant ? d.nonCompliant + " of " + d.total + " agents not compliant" : "all " + d.total + " agents compliant", status: d.nonCompliant ? "error" : "ok" }),
    h(DataTable, { columns: [{ key: "name", header: "Agent" }, { key: "adapterType", header: "Adapter" }, { key: "state", header: "State" }, { key: "detail", header: "Findings" }],
      rows: d.results.map((r) => ({ id: r.id, name: r.name, adapterType: r.adapterType, state: r.compliant ? "ok" : "drift", detail: r.findings.join("; ") })), emptyMessage: "No agents." }));
}

// ---------------------------------------------------------------------------------------------------- ITSec agent
// The plugin-managed security agent of the host company. Reads and writes go through actions (identity checked in the
// worker; writes are admin-only). The agent's configuration is fixed when Paperclip creates it: this card shows what the
// plugin verified and the PATCH for an advisory model, it cannot change the agent.
const ITSEC_KEYS = ["itsecHostCompanyId", "itsecModel", "itsecContext"];
function ItsecCard({ context, site, onSaved }) {
  const status = usePluginAction("itsecStatus");
  const check = usePluginAction("itsecCheck");
  const reset = usePluginAction("itsecReset");
  const save = usePluginAction("saveSettings");
  const [st, setSt] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [form, setForm] = useState({ model: "", context: "" });
  const [confirmReset, setConfirmReset] = useState(false);
  const load = async () => {
    try { const r = await status({}); setSt(r); setError(null); setForm({ model: r.advisoryModel ?? "", context: r.context ?? "" }); }
    catch (e) { setError(errText(e)); }
  };
  useEffect(() => { load(); }, [context?.companyId]);
  const run = async (fn) => {
    setBusy(true);
    try { await fn(); } catch (e) { setMessage({ tone: "error", text: errText(e) }); } finally { setBusy(false); }
  };
  const saveItsec = (hostCompanyId) => run(async () => {
    if (!site) { setMessage({ tone: "pending", text: "The site settings are still loading; try again in a moment." }); return; }
    const r = await save({ settings: { ...(site ?? {}), itsecHostCompanyId: hostCompanyId, itsecModel: form.model, itsecContext: form.context } });
    setMessage(r.ok ? { tone: "ok", text: r.itsec?.ensure && r.itsec.ensure.ok === false ? `Saved, but the ITSec agent is not ready: ${r.itsec.ensure.error}${r.itsec.ensure.hint ? ` ${r.itsec.ensure.hint}` : ""}` : "ITSec settings saved." } : { tone: "error", text: r.errors.join("; ") });
    await load();
    if (onSaved) onSaved();
  });
  const onCheck = () => run(async () => {
    const r = await check({});
    setMessage(r.ok ? { tone: "ok", text: `Checked: ${r.verify?.state ?? "done"}.` } : { tone: "error", text: `${r.error ?? "failed"}${r.hint ? ` ${r.hint}` : ""}` });
    await load();
  });
  const onReset = () => run(async () => {
    const r = await reset({ confirm: true });
    setConfirmReset(false);
    setMessage(r.ok ? { tone: "ok", text: "ITSec agent and routines reset to the plugin's declaration." } : { tone: "error", text: r.error });
    await load();
  });
  if (error) return h("section", { style: box }, h("h3", null, "ITSec agent"), h("p", null, "Error: " + error));
  if (!st) return h("section", { style: box }, h("h3", null, "ITSec agent"), h("p", null, "Loading..."));
  const here = st.here;
  const v = st.state?.lastVerify;
  const editor = h("div", { style: { display: "grid", gap: 8 } },
    h("label", { style: { display: "grid", gap: 4 } }, h("span", null, "Model (advisory)"),
      h("span", { style: muted }, `The agent is created with ${st.createdModel}. Paperclip does not let the plugin change an existing agent, so a different model here is shown as a PATCH for the board to apply.`),
      h("select", { value: form.model, disabled: !st.admin, onChange: (e) => setForm({ ...form, model: e.target.value }) },
        h("option", { value: "" }, `as created (${st.createdModel})`), (st.models ?? []).map((m) => h("option", { key: m, value: m }, m)))),
    st.admin ? h("label", { style: { display: "grid", gap: 4 } }, h("span", null, "Notes about this host for the agent"),
      h("span", { style: muted }, "Written into the agent's itsec-context document: what this host is called, which knowledge-base project to search, the operator's rules. No secrets: agents can read it."),
      h("textarea", { rows: 4, value: form.context, onChange: (e) => setForm({ ...form, context: e.target.value }) })) : null);
  return h("section", { style: { ...box, display: "grid", gap: 8 } },
    h("h3", null, "ITSec agent"),
    h("p", { style: muted }, "A sandboxed security agent the plugin creates in ONE company, the host company. It triages the alert issues of that company (it closes one only after a resolution comment with evidence, otherwise it escalates to the owner) and reviews the host's safety automation daily. Nothing is created until a company is marked."),
    message ? h(StatusBadge, { label: message.text, status: message.tone }) : null,
    !st.configured ? h("div", { style: { display: "grid", gap: 8 } },
      h("p", null, "No host company is marked: there is no ITSec agent."),
      st.admin ? h("div", null, editor, h("button", { type: "button", disabled: busy || !context?.companyId, onClick: () => saveItsec(context.companyId) }, "Mark this company as the host company and create the agent")) : h("p", { style: muted }, "Only plugin admins can mark a company."))
    : !here ? h("div", { style: { display: "grid", gap: 8 } },
      h("p", null, `The host company is ${st.hostCompanyId}. Open this page inside that company to see and manage the agent.`),
      st.admin ? h("div", null, h("button", { type: "button", disabled: busy, onClick: () => saveItsec("") }, "Clear the host company (pauses the old agent)")) : null)
    : h("div", { style: { display: "grid", gap: 8 } },
      h("div", { style: { display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" } },
        h(StatusBadge, { label: st.agent ? `agent ${st.agent.status}${st.agent.status === "paused" && st.agent.pauseReason ? ` (${st.agent.pauseReason})` : ""}` : "agent not created", status: st.agent?.status === "idle" || st.agent?.status === "running" ? "ok" : "pending" }),
        v ? h(StatusBadge, { label: v.ok ? "verified" : `verification: ${v.state}`, status: v.ok ? "ok" : "error" }) : null),
      v && v.findings?.length ? h("ul", { style: { margin: 0 } }, v.findings.map((f, i) => h("li", { key: i }, f))) : null,
      (st.attention ?? []).map((t, i) => h("p", { key: `a${i}` }, t)),
      st.state?.lastError && !(st.attention ?? []).includes(st.state.lastError.message) ? h("p", null, `Not ready: ${st.state.lastError.message}${st.state.lastError.hint ? ` ${st.state.lastError.hint}` : ""}`) : null,
      (st.warnings ?? []).map((w, i) => h("p", { key: i, style: { color: "#c33" } }, w)),
      st.agent?.defaultDrift ? h("p", { style: muted }, `Its instructions differ from this plugin version (${(st.agent.defaultDrift.changedFiles ?? []).join(", ")}). Reset re-applies them, and also the sandbox configuration, wiping board edits.`) : null,
      h("div", null, h("b", null, "Model: "), `${st.liveModel ?? "unknown"} (live)`, st.advisoryModel ? `, wanted: ${st.advisoryModel}` : ""),
      st.modelPatch ? h("pre", { style: { ...muted, whiteSpace: "pre-wrap" } }, `${st.modelPatch.method} ${st.modelPatch.path}\n${JSON.stringify(st.modelPatch.body)}\n${st.modelPatch.note}`) : null,
      h("div", null, h("b", null, "Routines"), h("ul", { style: { margin: "4px 0 0 18px" } }, (st.routines ?? []).map((r) => h("li", { key: r.key },
        `${r.key}: ${r.status}`, r.declared?.length ? `, declared schedule: ${r.declared.map((t) => `${t.kind} ${t.cron ?? ""} ${t.timezone ?? ""}`.trim()).join("; ")}` : ", no schedule of its own (started by alerts)"))),
        h("span", { style: muted }, "The schedule shown is the one the plugin declared when it created the routine. The live schedule is on the Routines page of Paperclip, where it can also be changed: the plugin cannot.")),
      h("div", { style: muted }, `Last triage started: ${st.state?.lastNudgeAt ?? "never"}. Open alerts without a verdict: ${st.state?.untriaged ?? "unknown"}.`),
      editor,
      st.admin ? h("div", { style: { display: "flex", gap: 8, flexWrap: "wrap" } },
        h("button", { type: "button", disabled: busy, onClick: () => saveItsec(st.hostCompanyId) }, "Save ITSec settings"),
        h("button", { type: "button", disabled: busy, onClick: onCheck }, "Check now"),
        confirmReset ? h("span", null, "Reset re-applies the plugin's declaration and wipes the board's edits to the agent. ",
          h("button", { type: "button", disabled: busy, onClick: onReset }, "Yes, reset"), " ", h("button", { type: "button", disabled: busy, onClick: () => setConfirmReset(false) }, "Cancel"))
          : h("button", { type: "button", disabled: busy, onClick: () => setConfirmReset(true) }, "Reset to the plugin's declaration"),
        h("button", { type: "button", disabled: busy, onClick: () => saveItsec("") }, "Clear the host company (pauses the agent)")) : null),
    st.notice ? h("p", { style: muted }, `The ITSec agent of the previously marked company was paused at ${st.notice.at}. The plugin never deletes it; the board may.`) : null,
    st.retirePending?.length ? h("p", { style: muted }, `Still to pause (retried right after the request and then every 15 minutes): ${st.retirePending.map((q) => q.companyId).join(", ")}.`) : null);
}

export function HardeningPage({ context }) {
  const status = usePluginData("hardening-status", {});
  const settings = usePluginData("hardening-settings", {});
  const planChange = usePluginAction("planChange");
  const applyChange = usePluginAction("applyChange");
  const restart = usePluginAction("restart");
  const restoreAll = usePluginAction("restoreAll");
  const saveSettings = usePluginAction("saveSettings");
  const runSelfTest = usePluginAction("runSelfTest");
  const hostInstallCommand = usePluginAction("hostInstallCommand");
  const [hostModal, setHostModal] = useState(null);
  const fromStatus = (d) => (d?.protections ? Object.fromEntries(d.protections.map((p) => [p.id, p.enabled])) : null);
  const [desired, setDesired] = useState(() => fromStatus(status.data));
  const [plan, setPlan] = useState(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [confirmRestore, setConfirmRestore] = useState(false);

  const s = status.data;
  useEffect(() => { if (s?.protections) setDesired(fromStatus(s)); }, [s]);
  const refresh = () => { status.refresh(); settings.refresh(); };
  const run = async (fn) => {
    setBusy(true); setMessage(null);
    try { await fn(); } catch (e) { setMessage({ tone: "error", text: errText(e) }); } finally { setBusy(false); }
  };

  if (status.loading && !s) return h("p", null, "Loading...");
  if (status.error) return h("p", null, "Error: " + errText(status.error));
  if (!s) return null;

  const rows = s.protections;
  const switchable = (p) => !p.placeholder && !p.managedElsewhere && !p.hostInstall;
  const enabledNow = rows.filter((p) => switchable(p) && p.enabled).map((p) => p.id);
  const wanted = desired ? rows.filter((p) => switchable(p) && desired[p.id]).map((p) => p.id) : enabledNow;
  const dirty = wanted.join(",") !== enabledNow.join(",");

  const onSave = () => run(async () => { setConfirmed(false); setPlan(await planChange({ enabled: wanted })); });
  const onApply = () => run(async () => {
    const r = await applyChange({ enabled: plan.enabled, confirmCoreOff: confirmed });
    if (!r.ok) { setMessage({ tone: "error", text: r.error }); return; }
    setPlan(null);
    setMessage({ tone: "ok", text: r.changed.length ? `Applied. ${r.changed.length} file(s) rebuilt; restart Paperclip to activate.` : "Applied; no file changes." });
    refresh();
  });
  const onRestart = () => run(async () => {
    const r = await restart({});
    setMessage(r.manual ? { tone: "warning", text: r.message } : { tone: r.ok ? "ok" : "error", text: r.ok ? "Restart requested; this page reconnects when Paperclip is back." : `Restart failed: ${r.output}` });
  });
  const onRestore = () => run(async () => {
    const r = await restoreAll({ confirm: true });
    setConfirmRestore(false);
    setMessage(r.ok ? { tone: "ok", text: `Originals restored (${r.restored.length} file(s))${r.skipped.length ? `; left alone: ${r.skipped.map((x) => x.rel).join(", ")}` : ""}. Restart Paperclip to activate.` } : { tone: "error", text: r.error });
    refresh();
  });
  const onHostSwitch = (p, on) => run(async () => {
    const kind = p.id === "watchdog" ? "watchdog" : "hermes";
    const mode = on ? "install" : "uninstall";
    setHostModal({ kind, mode, id: p.id, result: null });
    const result = await hostInstallCommand({ kind, mode });
    setHostModal({ kind, mode, id: p.id, result });
  });
  const onSelfTest = () => run(async () => {
    const r = await runSelfTest({});
    setMessage(!r.ran ? { tone: "pending", text: r.reason } : r.ok ? { tone: "ok", text: "Self-test passed for every applied protection." } : { tone: "error", text: `Self-test failed: ${r.failed.join(", ")}` });
    refresh();
  });
  const onSaveSettings = (form) => run(async () => {
    // The ITSec card owns its three keys; the site form does not send them.
    const r = await saveSettings({ settings: Object.fromEntries(Object.entries(form).filter(([k]) => !ITSEC_KEYS.includes(k))) });
    setMessage(r.ok ? { tone: "ok", text: r.configChanged ? `Settings saved to ${r.configPath}. Paperclip reads this file only at startup, so restart it to use them.` : "Settings saved (no change)." } : { tone: "error", text: r.errors.join("; ") });
    refresh();
  });

  const r = s.restart;
  return h("div", { style: { display: "grid", gap: 16, maxWidth: 980 } },
    h("h2", null, "Security hardening"),
    !s.available ? h("div", { style: { ...box, borderColor: "rgba(220,60,60,0.6)", display: "grid", gap: 4 } },
      h("strong", null, "The plugin cannot tell which Paperclip install to change, so it changes nothing."),
      h("span", null, s.reason),
      s.target?.ok === false ? h("span", { style: muted }, "Apply or restore with the command-line tool on the host: plugin/bin/hardening-engine.mjs (see its README).") : null)
      : h("div", { style: { display: "grid", gap: 2 } },
        h("p", { style: { ...muted, margin: 0 } }, `Paperclip ${s.paperclipVersion ?? "?"} at ${s.tree}. Switches apply to the whole install (every company).`),
        s.target ? h("p", { style: { ...muted, margin: 0 } }, `Instance ${s.target.instanceId ?? "?"}, data ${s.target.dataDir}, restart ${s.target.restartUnit ? `via systemd user unit ${s.target.restartUnit}` : `by hand (${s.target.restartNote ?? "no systemd unit"})`}.`) : null),
    message ? h(StatusBadge, { label: message.text, status: message.tone }) : null,
    r?.needed ? h("div", { style: { ...box, display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" } },
      h(StatusBadge, { label: r.settingsChanged ? "Restart needed (settings changed)" : "Restart needed", status: "pending" }),
      r.canRestart ? h("button", { type: "button", disabled: busy, onClick: onRestart }, "Restart Paperclip")
        : h("span", null, r.manualText ?? `Restart Paperclip now${r.reason ? ` (${r.reason})` : ""}.`),
      r.why ? h("span", { style: muted }, r.why) : null) : null,
    h("table", { style: { width: "100%", borderCollapse: "collapse" } },
      h("thead", null, h("tr", null, ["Protection", "Status", "Switch"].map((t) => h("th", { key: t, style: { textAlign: "left", padding: 6 } }, t)))),
      h("tbody", null, rows.map((p) => {
        const st = STATUS[p.status] ?? STATUS.unknown;
        return h("tr", { key: p.id, style: { borderTop: "1px solid rgba(127,127,127,0.2)" } },
          h("td", { style: { padding: 6 } }, h("div", null, h("b", null, p.title), p.core ? h("span", { style: muted }, " (safety core)") : null),
            h("div", { style: muted }, p.description), p.reason && !p.placeholder ? h("div", { style: muted }, p.reason) : null),
          h("td", { style: { padding: 6 } }, h(StatusBadge, { label: st.label, status: st.tone }),
            p.status === "applied" || p.status === "selftest-failed" ? h("div", { style: muted }, selfTestText(p.selfTest)) : null),
          h("td", { style: { padding: 6 } }, p.managedElsewhere ? h("span", { style: muted }, "Agent boxes page")
            : p.hostInstall ? h(Switch, { label: p.title, checked: p.enabled, disabled: busy, onChange: (v) => onHostSwitch(p, v) })
            : h(Switch, { label: p.title, checked: p.placeholder ? false : desired?.[p.id], disabled: p.placeholder || busy || !s.available,
            onChange: (v) => { setPlan(null); setDesired({ ...desired, [p.id]: v }); } })));
      }))),
    h("div", { style: { display: "flex", gap: 8 } },
      h("button", { type: "button", disabled: busy || !dirty || !s.available, onClick: onSave }, "Save"),
      h("button", { type: "button", disabled: busy || !s.available, onClick: onSelfTest }, "Run self-test"),
      s.selfTest?.waitingRestart ? h("span", { style: muted }, "Self-test waits for the next restart.") : null,
      dirty ? h("button", { type: "button", disabled: busy, onClick: () => { setPlan(null); setDesired(Object.fromEntries(rows.map((p) => [p.id, p.enabled]))); } }, "Discard") : null),
    plan ? h("div", { style: { display: "grid", gap: 8 } },
      h(PlanView, { plan, confirmed, setConfirmed }),
      h("div", { style: { display: "flex", gap: 8 } },
        h("button", { type: "button", disabled: busy || (plan.confirmationNeeded.length > 0 && !confirmed), onClick: onApply }, "Apply"),
        h("button", { type: "button", disabled: busy, onClick: () => setPlan(null) }, "Cancel"))) : null,
    h(HostInstallModal, { open: hostModal, row: hostModal ? rows.find((x) => x.id === hostModal.id) : null, onClose: () => { setHostModal(null); refresh(); }, refresh: () => status.refresh() }),
    s.watchdog?.recentAlerts?.length ? h("section", { style: box },
      h("h3", null, "Recent watchdog alerts"),
      h("ul", { style: { margin: 0 } }, s.watchdog.recentAlerts.map((a, i) => h("li", { key: i }, `${a.at} ${a.identifier ?? ""} ${a.title}`)))) : null,
    h("section", { style: box },
      h("h3", null, "Restore originals"),
      h("p", { style: muted }, "Switches every protection off and puts Paperclip's original files back exactly. A restart activates it."),
      confirmRestore ? h("div", { style: { display: "flex", gap: 8, alignItems: "center" } },
        h("span", null, "Really switch off every protection and restore the original files?"),
        h("button", { type: "button", disabled: busy, onClick: onRestore }, "Yes, restore originals"),
        h("button", { type: "button", disabled: busy, onClick: () => setConfirmRestore(false) }, "Cancel"))
        : h("button", { type: "button", disabled: busy || !s.available, onClick: () => setConfirmRestore(true) }, "Restore originals")),
    h("section", { style: box },
      h("h3", null, "Site settings"),
      h(SettingsForm, { settings: settings.data?.settings, userId: context?.userId, onSave: onSaveSettings, busy })),
    h(ItsecCard, { context, site: settings.data?.settings, onSaved: () => settings.refresh() }),
    h("section", { style: box }, h("h3", null, "Agent sandbox compliance (this company)"), h(Compliance, { companyId: context?.companyId })),
    h("p", { style: muted }, `Settings file: ${s.configPath ?? "unknown"}. Only instance admins can change protections or settings.`));
}

// ---------------------------------------------------------------------------------------------------- Agent boxes
// One row per agent that exists in the picked company (fresh at every refresh): box, hosts, read-only paths,
// permissions, status and today's tokens against the daily cap. Reads and writes go through actions (only actions
// carry the caller's identity); the worker re-checks every write (admin only).
const BOX = {
  allowlist: { label: "allowlist", tone: "ok" },
  "public-web": { label: "public web (*:443, *:80)", tone: "warning" },
  none: { label: "NONE = host network", tone: "error" },
  hidden: { label: "allowlist or public web (hidden by Paperclip)", tone: "info" },
  "hermes-wrapper": { label: "Hermes wrapper", tone: "ok" },
  unsupported: { label: "no sandbox support", tone: "error" },
};
const SYNC = {
  "in-sync": { label: "Paperclip matches", tone: "ok" },
  differs: { label: "Paperclip differs: apply the PATCH", tone: "warning" },
  unverifiable: { label: "cannot verify (Paperclip hides hosts)", tone: "info" },
};
const n0 = (v) => (v === null || v === undefined ? "-" : Number(v).toLocaleString("en-US"));
const red = { color: "rgb(200,40,40)", fontWeight: 600 };
const cell = { padding: 6, verticalAlign: "top" };
const yesNo = (v) => (v === true ? "yes" : v === false ? "no" : v === "derived" ? "derived" : "?");

function permissionsText(p) {
  return h("div", { style: { fontSize: "0.9em" } },
    h("div", null, "canCreateAgents: ", h("b", { style: p.canCreateAgents ? red : null }, yesNo(p.canCreateAgents))),
    h("div", null, "canCreateSkills: ", h("b", { style: p.canCreateSkills ? red : null }, yesNo(p.canCreateSkills))),
    h("div", null, "tasks:assign: ", h("b", null, yesNo(p.tasksAssign))),
    h("div", null, "pipelines:write: ", h("b", null, yesNo(p.pipelinesWrite))));
}

function listCell(items, base, hidden) {
  return h("div", { style: { fontFamily: "monospace", fontSize: "0.85em" } },
    items.length ? items.map((x) => h("div", { key: x, style: base.includes(x) ? muted : null }, x, base.includes(x) ? " (base)" : "")) : h("span", { style: muted }, "none"),
    hidden ? h("div", { style: muted }, `+ ${hidden} hidden by Paperclip`) : null);
}

function capCell(row, canEdit, draft, setDraft, onSave, busy) {
  const c = row.cap;
  if (!c) return h("span", { style: muted }, "-");
  if (!c.reported) return h("div", null, h(StatusBadge, { label: "usage not reported", status: "info" }), h("div", { style: muted }, "never paused by a cap"));
  const over = c.used !== null && c.used > c.cap;
  return h("div", { style: { display: "grid", gap: 4 } },
    h("div", { style: over ? red : null }, `${n0(c.used)} / ${n0(c.cap)}`, c.override !== null ? " (own cap)" : " (default)"),
    c.error ? h("div", { style: red }, `not measured: ${c.error}`) : null,
    c.pausedByCap ? h(StatusBadge, { label: "paused by caps", status: "warning" }) : null,
    canEdit ? h("div", { style: { display: "flex", gap: 4 } },
      h("input", { type: "text", "aria-label": `Own cap for ${row.name}`, placeholder: "default", value: draft ?? (c.override ?? ""), size: 10, onChange: (e) => setDraft(e.target.value) }),
      h("button", { type: "button", disabled: busy, onClick: () => onSave(draft ?? (c.override ?? "")) }, "Set")) : null);
}

function BoxEditor({ row, onSave, onCancel, busy }) {
  const [form, setForm] = useState(() => ({ mode: row.plugin.mode, extraHosts: listText(row.plugin.extraHosts), extraPaths: listText(row.plugin.extraPaths) }));
  const xor = row.permissions.tasksAssign !== false;
  return h("div", { style: { ...box, display: "grid", gap: 8 } },
    h("strong", null, `Box of ${row.name}`),
    h("label", null, "Box: ",
      h("select", { value: form.mode, onChange: (e) => setForm({ ...form, mode: e.target.value }) },
        h("option", { value: "allowlist" }, "allowlist"),
        h("option", { value: "public-web", disabled: xor }, `public web (*:443, *:80)${xor ? ": refused, this agent may assign work" : ""}`))),
    h("label", { style: { display: "grid", gap: 4 } }, h("span", null, "Extra hosts (host or host:port, one per line)"),
      h("span", { style: muted }, `Always included from the site settings: ${row.baseHosts.join(", ") || "none"}`),
      h("textarea", { rows: 3, value: form.extraHosts, onChange: (e) => setForm({ ...form, extraHosts: e.target.value }), style: { fontFamily: "monospace" } })),
    h("label", { style: { display: "grid", gap: 4 } }, h("span", null, "Extra read-only paths (absolute, one per line)"),
      h("span", { style: muted }, `Always included from the site settings: ${row.basePaths.join(", ") || "none"}`),
      h("textarea", { rows: 3, value: form.extraPaths, onChange: (e) => setForm({ ...form, extraPaths: e.target.value }), style: { fontFamily: "monospace" } })),
    h("div", { style: { display: "flex", gap: 8 } },
      h("button", { type: "button", disabled: busy, onClick: () => onSave(form) }, "Save box"),
      h("button", { type: "button", disabled: busy, onClick: onCancel }, "Cancel")));
}

function CapsForms({ caps, canEdit, busy, onSaveCompany, onSaveInstall }) {
  const [c, setC] = useState(() => ({ defaultCap: caps.defaultCap, companyCap: caps.companyCap, mode: caps.mode, statusIssueId: caps.statusIssueId ?? "" }));
  const [t, setT] = useState(() => ({ defaultCap: caps.template.defaultCap, companyCap: caps.template.companyCap, mode: caps.template.mode, hermesStateDbs: listText(caps.hermesStateDbs) }));
  useEffect(() => { setC({ defaultCap: caps.defaultCap, companyCap: caps.companyCap, mode: caps.mode, statusIssueId: caps.statusIssueId ?? "" }); }, [caps]);
  const field = (obj, set, k, label, hint) => h("label", { style: { display: "grid", gap: 2 } }, h("span", null, label), hint ? h("span", { style: muted }, hint) : null,
    h("input", { type: "text", value: obj[k] ?? "", disabled: !canEdit, onChange: (e) => set({ ...obj, [k]: e.target.value }), style: { fontFamily: "monospace" } }));
  const mode = (obj, set) => h("label", null, "Mode: ", h("select", { value: obj.mode, disabled: !canEdit, onChange: (e) => set({ ...obj, mode: e.target.value }) },
    h("option", { value: "enforce" }, "enforce (pause over-cap agents)"), h("option", { value: "report" }, "report only (comment, never pause)"), h("option", { value: "off" }, "off (measure only)")));
  return h("div", { style: { display: "grid", gap: 16 } },
    h("div", { style: { display: "grid", gap: 8 } },
      h("h4", null, "This company"),
      h("p", { style: muted }, `Today (${caps.date}, UTC): ${n0(caps.companyUsed)} of ${n0(caps.companyCap)} tokens${caps.measuredAt ? ` (measured ${caps.measuredAt})` : " (not measured yet today; the job runs every 5 minutes)"}.${caps.fromTemplate ? " Uses the install-wide template until the job first sees this company." : ""}`),
      field(c, setC, "defaultCap", "Default cap per agent (tokens per UTC day)", "Applies to every agent without its own cap, including agents added later."),
      field(c, setC, "companyCap", "Company cap (all agents together, per UTC day)", "Over it, every agent that reports usage is paused."),
      mode(c, setC),
      field(c, setC, "statusIssueId", "Status issue id", "Pauses, resumes and the daily summary are posted here as comments; empty: activity log only."),
      canEdit ? h("div", null, h("button", { type: "button", disabled: busy, onClick: () => onSaveCompany(c) }, "Save company caps")) : null),
    h("div", { style: { display: "grid", gap: 8 } },
      h("h4", null, "Template for new companies (install-wide)"),
      field(t, setT, "defaultCap", "Default cap per agent"),
      field(t, setT, "companyCap", "Company cap"),
      mode(t, setT),
      h("label", { style: { display: "grid", gap: 2 } }, h("span", null, "Hermes state.db files"), h("span", { style: muted }, "Where Hermes keeps its session totals (absolute paths). Empty: ~/.hermes/state.db and ~/.hermes/profiles/*/state.db."),
        h("textarea", { rows: 2, value: t.hermesStateDbs, disabled: !canEdit, onChange: (e) => setT({ ...t, hermesStateDbs: e.target.value }), style: { fontFamily: "monospace" } })),
      canEdit ? h("div", null, h("button", { type: "button", disabled: busy, onClick: () => onSaveInstall(t) }, "Save template")) : null));
}

export function AgentBoxesPage({ context }) {
  const listCompanies = usePluginAction("listCompanies");
  const view = usePluginAction("agentBoxes");
  const takeOver = usePluginAction("takeOverBox");
  const saveBox = usePluginAction("saveBox");
  const saveCompanyCaps = usePluginAction("saveCompanyCaps");
  const saveAgentCap = usePluginAction("saveAgentCap");
  const saveCapsInstall = usePluginAction("saveCapsInstall");
  const [companies, setCompanies] = useState(null);
  const [target, setTarget] = useState(context?.companyId ?? "");
  const [data, setData] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);
  const [editing, setEditing] = useState(null);
  const [lastPatch, setLastPatch] = useState(null);
  const [drafts, setDrafts] = useState({});

  const load = async (cid) => {
    setLoadError(null);
    try { setData(await view({ targetCompanyId: cid })); } catch (e) { setLoadError(errText(e)); }
  };
  useEffect(() => { listCompanies({}).then(setCompanies, (e) => setLoadError(errText(e))); }, []);
  useEffect(() => { if (target) load(target); }, [target]);
  const run = async (fn) => {
    setBusy(true); setMessage(null);
    try { await fn(); } catch (e) { setMessage({ tone: "error", text: errText(e) }); } finally { setBusy(false); }
  };
  const result = (r, okText) => {
    if (r.ok) setMessage({ tone: "ok", text: okText });
    else setMessage({ tone: "error", text: r.error ?? (r.errors ?? []).join("; ") });
    return r.ok;
  };

  const onTakeOver = (row) => run(async () => {
    const r = await takeOver({ targetCompanyId: target, agentId: row.id });
    if (result(r, `${row.name} taken over.${r.notes?.length ? ` Note: ${r.notes.join("; ")}.` : ""}`)) await load(target);
  });
  const onSaveBox = (row, form) => run(async () => {
    const r = await saveBox({ targetCompanyId: target, agentId: row.id, mode: form.mode, extraHosts: form.extraHosts, extraPaths: form.extraPaths });
    if (result(r, r.applied ? `${row.name}: box saved and applied.` : `${row.name}: box saved in the plugin. ${r.note ?? r.applyError ?? ""}`)) {
      setEditing(null); setLastPatch({ name: row.name, method: r.method, path: r.path, patch: r.patch, applied: r.applied }); await load(target);
    }
  });
  const onSaveCap = (row, value) => run(async () => {
    const r = await saveAgentCap({ targetCompanyId: target, agentId: row.id, cap: value === "" ? null : value });
    if (result(r, r.cap === null ? `${row.name} uses the company default again.` : `${row.name} capped at ${n0(r.cap)} tokens per day.`)) { setDrafts({ ...drafts, [row.id]: undefined }); await load(target); }
  });
  const onSaveCompany = (c) => run(async () => { if (result(await saveCompanyCaps({ targetCompanyId: target, ...c }), "Company caps saved.")) await load(target); });
  const onSaveInstall = (t) => run(async () => {
    if (result(await saveCapsInstall({ targetCompanyId: target, template: { defaultCap: t.defaultCap, companyCap: t.companyCap, mode: t.mode }, hermesStateDbs: t.hermesStateDbs }), "Template saved (applies to companies the job has not seen yet).")) await load(target);
  });

  const d = data;
  const list = companies?.companies ?? [];
  return h("div", { style: { display: "grid", gap: 16, maxWidth: 1280 } },
    h("h2", null, "Agent boxes"),
    h("div", { style: { display: "flex", gap: 8, alignItems: "center" } },
      h("label", null, "Company: ",
        h("select", { value: target, disabled: busy || list.length < 2, onChange: (e) => { setEditing(null); setLastPatch(null); setTarget(e.target.value); } },
          list.length ? list.map((c) => h("option", { key: c.id, value: c.id }, c.name ?? c.id)) : h("option", { value: target }, target || "-"))),
      h("button", { type: "button", disabled: busy || !target, onClick: () => load(target) }, "Refresh"),
      d ? h("span", { style: muted }, `Read from Paperclip at ${d.checkedAt}`) : null),
    message ? h(StatusBadge, { label: message.text, status: message.tone }) : null,
    loadError ? h(StatusBadge, { label: `Error: ${loadError}`, status: "error" }) : null,
    d && !d.applySupported ? h("div", { style: { ...box, borderColor: "rgba(220,160,40,0.6)" } },
      h("strong", null, "Box values in Paperclip are read-only for this plugin. "), d.applyNote) : null,
    d && !d.grantsReadable ? h(StatusBadge, { label: "Agent grants could not be read: tasks:assign is unknown, so public web is refused for every agent.", status: "warning" }) : null,
    !d ? (loadError ? null : h("p", null, "Loading...")) : h("table", { style: { width: "100%", borderCollapse: "collapse" } },
      h("thead", null, h("tr", null, ["Agent", "Adapter / model", "Box", "Allowlist hosts", "Extra read-only paths", "Permissions", "Status", "Today / daily cap", ""].map((t) => h("th", { key: t, style: { textAlign: "left", padding: 6 } }, t)))),
      h("tbody", null, d.rows.length ? d.rows.map((row) => {
        const b = BOX[row.box] ?? { label: row.box, tone: "info" };
        return h("tr", { key: row.id, style: { borderTop: "1px solid rgba(127,127,127,0.2)", background: row.red ? "rgba(220,60,60,0.06)" : undefined } },
          h("td", { style: cell }, h("b", null, row.name), row.role ? h("div", { style: muted }, row.role) : null),
          h("td", { style: cell }, h("div", null, row.adapterType), h("div", { style: muted }, row.model || "(adapter default)")),
          h("td", { style: cell }, h(StatusBadge, { label: b.label, status: b.tone }),
            row.current.note ? h("div", { style: row.current.red ? red : muted }, row.current.note) : null,
            row.managed && row.sync ? h("div", null, h(StatusBadge, { label: (SYNC[row.sync] ?? SYNC.differs).label, status: (SYNC[row.sync] ?? SYNC.differs).tone })) : null,
            row.managed ? h("div", { style: muted }, "managed by the plugin") : null,
            row.conflicts.map((c) => h("div", { key: c, style: red }, `Conflict: ${c}`)),
            row.error ? h("div", { style: red }, row.error) : null),
          h("td", { style: cell }, row.boxable ? listCell(row.hosts, row.baseHosts, row.managed ? 0 : row.current.hiddenHosts) : h("span", { style: muted }, "-")),
          h("td", { style: cell }, row.boxable ? listCell(row.readOnlyPaths, row.basePaths, row.managed ? 0 : row.current.hiddenPaths) : h("span", { style: muted }, "-")),
          h("td", { style: cell }, permissionsText(row.permissions)),
          h("td", { style: cell }, row.status),
          h("td", { style: cell }, capCell(row, d.canEdit, drafts[row.id], (v) => setDrafts({ ...drafts, [row.id]: v }), (v) => onSaveCap(row, v), busy)),
          h("td", { style: cell }, !d.canEdit || !row.boxable ? null
            : row.managed ? h("button", { type: "button", disabled: busy, onClick: () => { setLastPatch(null); setEditing(row.id); } }, "Edit box")
              : h("button", { type: "button", disabled: busy, onClick: () => onTakeOver(row) }, "Take over")));
      }) : h("tr", null, h("td", { colSpan: 9, style: cell }, "No agents.")))),
    d && editing ? (() => { const row = d.rows.find((r) => r.id === editing); return row?.plugin ? h(BoxEditor, { key: row.id, row, busy, onSave: (f) => onSaveBox(row, f), onCancel: () => setEditing(null) }) : null; })() : null,
    lastPatch && !lastPatch.applied ? h("div", { style: { ...box, display: "grid", gap: 6 } },
      h("strong", null, `To apply ${lastPatch.name}'s box in Paperclip: ${lastPatch.method} ${lastPatch.path}`),
      h("p", { style: muted }, "Full lists from the plugin's settings (never a value read back from Paperclip). Send it as the board (UI or API)."),
      h("pre", { style: { fontFamily: "monospace", whiteSpace: "pre-wrap", margin: 0 } }, JSON.stringify(lastPatch.patch, null, 2))) : null,
    d?.caps ? h("section", { style: box }, h("h3", null, "Daily token caps"), h(CapsForms, { key: d.companyId, caps: d.caps, canEdit: d.canEdit, busy, onSaveCompany, onSaveInstall })) : null,
    h("p", { style: muted }, d?.canEdit ? "You can change boxes and caps (any company)."
      : `Read only. Your user id: ${context?.userId ?? "unknown"} (an instance admin adds it to "Users who may change protections" in this plugin's settings).`));
}
