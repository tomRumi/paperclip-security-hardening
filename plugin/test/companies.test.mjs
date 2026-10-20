// listCompanies and the jobs that use it when the host refuses `companies.list` (a company-scoped request, such as a
// delivered event, is still registered: "missing, expired, or unknown invocation scope"), see src/logic.js.
import test from "node:test";
import assert from "node:assert/strict";
import { listCompanies, noteCompanyEvent, KNOWN_COMPANIES_KEY, EVENT_SCOPE_HOLD_MS } from "../src/logic.js";
import { register } from "../src/worker.js";

const REFUSED = () => new Error('Plugin "p" is not allowed to perform "companies.list": the worker referenced a missing, expired, or unknown invocation scope');

function fakeCtx({ list } = {}) {
  const state = new Map();
  const k = (key) => `${key.scopeKind}:${key.scopeId ?? ""}:${key.stateKey}`;
  const writes = [];
  const infos = [];
  const warns = [];
  const reg = { jobs: {}, events: {}, actions: {}, data: {} };
  const ctx = {
    state: { get: async (key) => (state.has(k(key)) ? structuredClone(state.get(k(key))) : null), set: async (key, v) => { writes.push(k(key)); state.set(k(key), structuredClone(v)); } },
    companies: { list: list ?? (async () => []) },
    agents: { list: async () => [] },
    config: { get: async () => ({}) },
    activity: { log: async () => {} },
    logger: { info: (m) => infos.push(m), warn: (m) => warns.push(m), error() {}, debug() {} },
    data: { register: (key, fn) => { reg.data[key] = fn; } },
    actions: { register: (key, fn) => { reg.actions[key] = fn; } },
    jobs: { register: (key, fn) => { reg.jobs[key] = fn; } },
    events: { on: (name, fn) => { reg.events[name] = fn; } },
  };
  return { ctx, state, writes, infos, warns, reg, k };
}

test("listCompanies: every successful listing replaces the remembered ids; an unchanged list writes nothing", async () => {
  const f = fakeCtx({ list: async () => [{ id: "c2" }, { id: "c1" }] });
  await listCompanies(f.ctx);
  assert.deepEqual(f.state.get(f.k(KNOWN_COMPANIES_KEY)), { ids: ["c1", "c2"] });
  const writes = f.writes.length;
  await listCompanies(f.ctx);
  assert.equal(f.writes.length, writes);
  f.ctx.companies.list = async () => [{ id: "c1" }];
  await listCompanies(f.ctx);
  assert.deepEqual(f.state.get(f.k(KNOWN_COMPANIES_KEY)), { ids: ["c1"] }, "a company that is gone drops out");
});

test("listCompanies: refused by the host -> the remembered ids (one attempt, no retry); none remembered -> the host's error", async () => {
  const f = fakeCtx({ list: async () => [{ id: "c1" }, { id: "c2" }] });
  await listCompanies(f.ctx);
  let asked = 0;
  f.ctx.companies.list = async () => { asked += 1; throw REFUSED(); };
  assert.deepEqual(await listCompanies(f.ctx), [{ id: "c1", name: null }, { id: "c2", name: null }]);
  assert.equal(asked, 1);
  assert.match(f.infos.join(), /refused by the host.*2 remembered/);
  const empty = fakeCtx({ list: async () => { throw REFUSED(); } });
  await assert.rejects(listCompanies(empty.ctx), /invocation scope/);
});

test("listCompanies: within 15 minutes of a delivered event the host is not even asked (it would refuse and log an error); later it is", async () => {
  let asked = 0;
  const f = fakeCtx({ list: async () => { asked += 1; return [{ id: "c1" }]; } });
  await listCompanies(f.ctx);
  assert.equal(asked, 1);
  const t0 = 1_000_000;
  await noteCompanyEvent(f.ctx, "c2", t0);
  assert.deepEqual((await listCompanies(f.ctx, { now: () => t0 + 60_000 })).map((c) => c.id), ["c1", "c2"]);
  assert.equal(asked, 1, "no host call");
  // A page request always asks the host (it admits the call inside its own company scope, and the page needs the names).
  assert.equal((await listCompanies(f.ctx, { now: () => t0 + 60_000, live: true })).length, 1);
  assert.equal(asked, 2);
  await listCompanies(f.ctx, { now: () => t0 + EVENT_SCOPE_HOLD_MS + 1 });
  assert.equal(asked, 3);
  // Nothing remembered yet: the host is asked even right after an event.
  const g = fakeCtx({ list: async () => { asked += 1; return [{ id: "c9" }]; } });
  await g.ctx.state.set(KNOWN_COMPANIES_KEY, { ids: [] });
  await noteCompanyEvent(g.ctx, null, t0);
  assert.deepEqual((await listCompanies(g.ctx, { now: () => t0 + 1 })).map((c) => c.id), ["c9"]);
});

test("listCompanies: any other error is passed on at once (no fallback)", async () => {
  const f = fakeCtx({ list: async () => { throw new Error("database down"); } });
  await f.ctx.state.set(KNOWN_COMPANIES_KEY, { ids: ["c1"] });
  await assert.rejects(listCompanies(f.ctx), /database down/);
});

test("noteCompanyEvent: adds an id once; a known id costs no write", async () => {
  const f = fakeCtx();
  await noteCompanyEvent(f.ctx, "c9");
  await noteCompanyEvent(f.ctx, "c3");
  assert.deepEqual(f.state.get(f.k(KNOWN_COMPANIES_KEY)), { ids: ["c3", "c9"] });
  const writes = f.writes.length;
  await noteCompanyEvent(f.ctx, "c9");
  await noteCompanyEvent(f.ctx, null);
  assert.equal(f.writes.length, writes);
});

test("the jobs that visit every company run through a refused companies.list on the remembered ids, an issue.updated event teaches a new company", async () => {
  let refuse = false;
  const asked = [];
  const f = fakeCtx({ list: async () => { if (refuse) throw REFUSED(); return [{ id: "c1" }]; } });
  f.ctx.agents.list = async ({ companyId }) => { asked.push(companyId); return []; };
  register(f.ctx, { hardening: { loadSettings: async () => ({}), getStatus: async () => ({}), getSettings: async () => ({}), setItsec() {}, assertAdmin: async () => ({}) }, itsec: { onAlert: async () => ({}) }, recheck: { recordEvent: async () => false, runJob: async () => [] } });
  await listCompanies(f.ctx); // what the worker does at start
  refuse = true;
  await f.reg.events["issue.updated"]({ companyId: "c7", entityId: "i1" });
  await f.reg.jobs["verify-sandbox-config"]();
  assert.deepEqual([...new Set(asked)].sort(), ["c1", "c7"]);
  // Also when no event was seen but the host refuses anyway.
  asked.length = 0;
  const g = fakeCtx({ list: async () => { throw REFUSED(); } });
  await g.ctx.state.set(KNOWN_COMPANIES_KEY, { ids: ["c4"] });
  g.ctx.agents.list = async ({ companyId }) => { asked.push(companyId); return []; };
  register(g.ctx, { hardening: { loadSettings: async () => ({}), getStatus: async () => ({}), getSettings: async () => ({}), setItsec() {}, assertAdmin: async () => ({}) }, itsec: { onAlert: async () => ({}) }, recheck: { recordEvent: async () => false, runJob: async () => [] } });
  await g.reg.jobs["verify-sandbox-config"]();
  assert.deepEqual(asked, ["c4"]);
});

const DEPS = { hardening: { loadSettings: async () => ({}), getStatus: async () => ({}), getSettings: async () => ({}), setItsec() {}, assertAdmin: async () => ({}) }, itsec: { onAlert: async () => ({}) }, recheck: { recordEvent: async () => false, runJob: async () => [] } };

test("verify-sandbox-config: one company that cannot be read (a stale remembered id) does not stop the others", async () => {
  const f = fakeCtx({ list: async () => { throw REFUSED(); } });
  await f.ctx.state.set(KNOWN_COMPANIES_KEY, { ids: ["stale", "c4"] });
  const asked = [];
  f.ctx.agents.list = async ({ companyId }) => { asked.push(companyId); if (companyId === "stale") throw new Error("company not found"); return []; };
  register(f.ctx, DEPS);
  await f.reg.jobs["verify-sandbox-config"]();
  assert.deepEqual(asked, ["stale", "c4"]);
  assert.ok(f.warns.some((m) => /stale.*skipped.*company not found/.test(m)));
});

test("verify-sandbox-config: asks the host for the companies at least hourly, also right after an event; the remembered ids serve the runs in between", async () => {
  const realNow = Date.now;
  let t = 1_800_000_000_000;
  Date.now = () => t;
  try {
    let asked = 0;
    const f = fakeCtx({ list: async () => { asked += 1; return [{ id: "c1" }]; } });
    register(f.ctx, DEPS);
    await f.reg.jobs["verify-sandbox-config"]();
    assert.equal(asked, 1, "the first run asks the host");
    t += 5 * 60_000;
    await f.reg.events["issue.updated"]({ companyId: "c1", entityId: "i1" });
    t += 5 * 60_000;
    await f.reg.jobs["verify-sandbox-config"]();
    assert.equal(asked, 1, "inside the event hold and within the hour: remembered ids");
    t += 45 * 60_000;
    await f.reg.events["issue.updated"]({ companyId: "c1", entityId: "i1" });
    t += 6 * 60_000;
    await f.reg.jobs["verify-sandbox-config"]();
    assert.equal(asked, 2, "an hour after the last real listing the host is asked, although an event arrived minutes ago");
  } finally { Date.now = realNow; }
});
