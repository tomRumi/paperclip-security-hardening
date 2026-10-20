// Alert tamper re-check (src/recheck.js, src/alerts.js trackAlert, wiring in src/worker.js) with a fake plugin
// context: issues live in a Map, close events are delivered the way the host's "issue.updated" event carries them
// (envelope actorType/actorId, payload = the activity details).
import test from "node:test";
import assert from "node:assert/strict";
import { raiseAlertIssue, ALERT_LOG_KEY } from "../src/alerts.js";
import { createAlertRecheck, recheckConfig, closesKey, MAX_RERAISE } from "../src/recheck.js";
import { register } from "../src/worker.js";

const T0 = Date.parse("2026-10-18T10:00:00.000Z");
const MIN = 60_000, DAY = 864e5;

function setup({ config = { adminUserIds: ["u-owner"] } } = {}) {
  const state = new Map(), issues = new Map(), created = [], logs = [];
  const clock = { t: T0 };
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const reads = [];
  const ctx = {
    state: {
      get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null),
      set: async (key, v) => { state.set(k(key), structuredClone(v)); },
      delete: async (key) => { state.delete(k(key)); },
    },
    config: { get: async (companyId) => (companyId === "c1" ? config : {}) },
    activity: { log: async (e) => { logs.push(e); } },
    issues: {
      create: async (input) => {
        created.push(input);
        const id = `i-${created.length}`;
        issues.set(id, { id, identifier: `ENG-${created.length}`, companyId: input.companyId, title: input.title, description: input.description, status: input.status, completedAt: null, cancelledAt: null, hiddenAt: null });
        return { id, identifier: `ENG-${created.length}` };
      },
      get: async (id, companyId) => { reads.push(id); const i = issues.get(id); return i && i.companyId === companyId ? structuredClone(i) : null; },
    },
    agents: { get: async (id) => (id === "a-rogue" ? { id, name: "Rogue Coder" } : null) },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
  };
  const r = createAlertRecheck({ ctx, now: () => clock.t });
  const raise = (title = "[Security hardening] Watchdog stopped reporting") =>
    raiseAlertIssue({ ctx, now: () => clock.t, settings: { alertCompanyId: "c1", alertProjectId: "p1" }, title, description: "evidence lines", metadata: { source: "watchdog" } });
  /** Close an issue as `actor` and deliver the host's event for it. */
  let n = 0;
  async function close(issueId, { actorType, actorId, agentId, status = "done", deliver = true }) {
    const at = new Date(clock.t).toISOString();
    Object.assign(issues.get(issueId), { status, ...(status === "done" ? { completedAt: at } : { cancelledAt: at }) });
    if (deliver) return r.recordEvent({ eventId: `ev-${++n}`, eventType: "issue.updated", occurredAt: at, actorType, actorId, entityId: issueId, entityType: "issue", companyId: "c1",
      payload: { identifier: "x", status, ...(agentId ? { agentId } : {}), _previous: { status: "todo" } } });
    return null;
  }
  const tracked = () => Object.keys(state.get(k(ALERT_LOG_KEY))?.issues ?? {});
  return { ctx, r, state, issues, created, logs, clock, raise, close, tracked, reads };
}

test("config: owners default to adminUserIds, days default 7, 0 = off, invalid days fall back", () => {
  assert.deepEqual(recheckConfig({ adminUserIds: ["u1"] }), { days: 7, owners: ["u1"] });
  assert.deepEqual(recheckConfig({ adminUserIds: ["u1"], alertOwnerUserIds: ["u2"], alertRecheckDays: 0 }), { days: 0, owners: ["u2"] });
  assert.equal(recheckConfig({ alertRecheckDays: -1 }).days, 7);
  assert.equal(recheckConfig({ alertRecheckDays: "3" }).days, 7);
});

test("an owner's close is accepted: no new issue, the alert stays tracked", async () => {
  const s = setup();
  const a = await s.raise();
  s.clock.t += 30 * MIN;
  assert.equal(await s.close(a.issue.issueId, { actorType: "user", actorId: "u-owner" }), true);
  s.clock.t += 5 * MIN;
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result), ["closed by owner"]);
  assert.equal(s.created.length, 1);
  assert.deepEqual(s.tracked(), [a.issue.issueId]);
});

test("an explicit alertOwnerUserIds list replaces adminUserIds", async () => {
  const s = setup({ config: { adminUserIds: ["u-owner"], alertOwnerUserIds: ["u-sec"] } });
  const a = await s.raise();
  await s.close(a.issue.issueId, { actorType: "user", actorId: "u-owner" });
  assert.deepEqual((await s.r.runJob()).map((x) => x.result), ["re-raised"]);
});

test("an agent's close triggers ONE HIGH re-raise naming the agent; a repeat run does not duplicate", async () => {
  const s = setup();
  const a = await s.raise();
  s.clock.t += 2 * 60 * MIN;
  // An agent run: the activity entry's actor is the agent (agentId in the details, as the old watchdog read it).
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", agentId: "a-rogue" });
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result), ["re-raised"]);
  assert.equal(s.created.length, 2);
  const again = s.created[1];
  assert.equal(again.priority, "high");
  assert.equal(again.companyId, "c1");
  assert.equal(again.projectId, "p1");
  assert.equal(again.assigneeAgentId, undefined, "wakes no agent");
  assert.equal(again.title, "[RE-RAISED] [Security hardening] Watchdog stopped reporting");
  assert.match(again.description, /closed \(done\) by agent Rogue Coder \(a-rogue\), who is not an alert owner/);
  assert.match(again.description, /Original issue: ENG-1/);
  assert.match(again.description, /evidence lines/);
  assert.ok(s.logs.some((l) => /Security hardening alert: \[RE-RAISED\]/.test(l.message) && l.metadata.closer.kind === "agent"));
  // The old issue is no longer checked; the new one is.
  assert.deepEqual(s.tracked(), ["i-2"]);
  assert.equal(s.state.has(`issue:${a.issue.issueId}:alert-closes`), false);
  for (let i = 0; i < 3; i++) { s.clock.t += 10 * MIN; await s.r.runJob(); }
  assert.equal(s.created.length, 2, "no duplicate on later runs");
  // The re-raised alert keeps its count and is re-checked itself.
  assert.equal((await s.ctx.state.get(ALERT_LOG_KEY)).issues["i-2"].reraised, 1);
});

test("another user's cancel triggers the re-raise too; an event delivered twice is stored once", async () => {
  const s = setup();
  const a = await s.raise();
  const ev = { eventId: "dup", eventType: "issue.updated", occurredAt: new Date(T0).toISOString(), actorType: "user", actorId: "u-other", entityId: a.issue.issueId, entityType: "issue", companyId: "c1", payload: { changes: { status: { from: "todo", to: "cancelled" } } } };
  Object.assign(s.issues.get(a.issue.issueId), { status: "cancelled", cancelledAt: ev.occurredAt });
  assert.equal(await s.r.recordEvent(ev), true);
  assert.equal(await s.r.recordEvent(ev), false);
  assert.equal((await s.ctx.state.get(closesKey(a.issue.issueId))).length, 1);
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result), ["re-raised"]);
  assert.match(s.created[1].description, /cancelled by user u-other, who is not an alert owner/);
  await s.r.runJob();
  assert.equal(s.created.length, 2);
});

test("a deleted alert is re-raised once (its actor is unknown); open or reopened alerts are left alone", async () => {
  const s = setup();
  const a = await s.raise();
  const b = await s.raise("[Security hardening] Self-test failed: Own box");
  s.issues.get(b.issue.issueId).status = "in_progress"; // status changes other than a close are not tampering
  s.issues.delete(a.issue.issueId);
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result).sort(), ["open", "re-raised"]);
  assert.match(s.created[2].description, /deleted by someone/);
  await s.r.runJob();
  assert.equal(s.created.length, 3);
});

test("a close whose event was missed: one MEDIUM 'closer unknown' alert, no re-raise, not repeated", async () => {
  const s = setup();
  const a = await s.raise();
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", deliver: false });
  assert.deepEqual((await s.r.runJob()).map((x) => x.result), ["closer unknown"]);
  assert.equal(s.created.length, 2);
  assert.equal(s.created[1].priority, "medium");
  assert.match(s.created[1].title, /closer unknown/);
  assert.equal((await s.r.runJob()).find((x) => x.issueId === a.issue.issueId).result, "closer unknown (alerted)");
  assert.equal(s.created.length, 2);
});

test("an old owner close does not cover a later close whose event was missed", async () => {
  const s = setup();
  const a = await s.raise();
  await s.close(a.issue.issueId, { actorType: "user", actorId: "u-owner" });
  s.clock.t += 60 * MIN;
  s.issues.get(a.issue.issueId).status = "todo";        // reopened
  s.clock.t += 60 * MIN;
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", deliver: false });
  assert.deepEqual((await s.r.runJob()).map((x) => x.result), ["closer unknown"]);
});

test("nothing is checked after the re-check window; the alert is dropped from tracking", async () => {
  const s = setup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 2 } });
  const a = await s.raise();
  s.clock.t += 2 * DAY + MIN;
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", agentId: "a-rogue" });
  const res = await s.r.runJob();
  assert.deepEqual(res.map((x) => x.result), ["window over"]);
  assert.deepEqual(s.reads, [], "the issue is not even read");
  assert.equal(s.created.length, 1);
  assert.deepEqual(s.tracked(), []);
});

test("re-check days 0 = off: nothing read, nothing raised", async () => {
  const s = setup({ config: { adminUserIds: ["u-owner"], alertRecheckDays: 0 } });
  const a = await s.raise();
  await s.close(a.issue.issueId, { actorType: "agent", actorId: "a-rogue", agentId: "a-rogue" });
  assert.deepEqual((await s.r.runJob()).map((x) => x.result), ["off"]);
  assert.deepEqual(s.reads, []);
  assert.equal(s.created.length, 1);
});

test(`re-raises stop after ${MAX_RERAISE} per alert chain (then only an activity entry)`, async () => {
  const s = setup();
  await s.raise();
  for (let i = 1; i <= MAX_RERAISE + 1; i++) {
    const id = s.tracked()[0];
    s.clock.t += MIN;
    await s.close(id, { actorType: "agent", actorId: "a-rogue", agentId: "a-rogue" });
    await s.r.runJob();
  }
  assert.equal(s.created.length, 1 + MAX_RERAISE);
  assert.equal(s.created.at(-1).title, "[RE-RAISED] [Security hardening] Watchdog stopped reporting", "the prefix is not stacked");
  assert.ok(s.logs.some((l) => /re-raise limit \(3\) reached/.test(l.message)));
  assert.deepEqual(s.tracked(), []);
});

test("events for issues that are not tracked alerts, and non-close changes, are ignored", async () => {
  const s = setup();
  const a = await s.raise();
  assert.equal(await s.r.recordEvent({ eventId: "e1", entityId: "other", entityType: "issue", actorType: "agent", actorId: "x", payload: { status: "done" } }), false);
  assert.equal(await s.r.recordEvent({ eventId: "e2", entityId: a.issue.issueId, entityType: "issue", actorType: "agent", actorId: "x", payload: { status: "in_progress" } }), false);
  assert.equal(await s.ctx.state.get(closesKey(a.issue.issueId)), null);
});

test("worker wiring: issue.updated is subscribed and the alert-recheck job re-raises", async () => {
  const s = setup();
  const reg = { jobs: {}, events: {} };
  const ctx = { ...s.ctx, data: { register() {} }, actions: { register() {} }, jobs: { register: (key, fn) => { reg.jobs[key] = fn; } },
    events: { on: (name, fn) => { reg.events[name] = fn; } } };
  register(ctx, { recheck: createAlertRecheck({ ctx, now: () => s.clock.t }) });
  assert.ok(reg.jobs["alert-recheck"] && reg.events["issue.updated"]);
  const a = await s.raise();
  Object.assign(s.issues.get(a.issue.issueId), { status: "done", completedAt: new Date(T0).toISOString() });
  await reg.events["issue.updated"]({ eventId: "w1", occurredAt: new Date(T0).toISOString(), actorType: "agent", actorId: "a-rogue", entityId: a.issue.issueId, entityType: "issue", companyId: "c1", payload: { status: "done" } });
  await reg.jobs["alert-recheck"]({ jobKey: "alert-recheck" });
  assert.equal(s.created.length, 2);
  assert.match(s.created[1].description, /agent Rogue Coder/);
});
