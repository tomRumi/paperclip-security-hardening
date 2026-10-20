// Patch 0027 (host/patches/0027-adapter-test-board-only.patch, server routes/agents.js): POST /companies/:id/adapters/:type/test-environment
// starts the adapter's probes on the server as the service user, outside any agent box, from the adapterConfig of the request. The route
// only asked for the right to create agents, which every CEO-role agent has. Now only a board user may start it.
// The route handler lives in a closure of a module that needs a database, so the test cuts the real handler head out of the file the
// engine builds from the ORIGINAL bytes (helpers/pristine.mjs; PAPERCLIP_STOCK_TREE_<vkey>) of each installed version, from the
// `router.post(".../test-environment"` line up to the first authorization call, and runs it with stubs for what it calls. Fail-before is the
// same file built without 0027: an agent actor reaches the authorization (and, behind it, the probes).
//   HARDENING_TEST_SCRATCH  scratch parent dir (default: the OS temp dir)
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SOURCE_PATCHES_DIR } from "../src/engine/index.js";
import { PATCHES, comparePatchIds } from "../src/engine/registry.js";
import { discoverPatchFiles, orderCandidates, readPatchTarget, buildFile } from "../src/engine/patches.js";
import { noPristineSkip, pristineOrNull, stockTreePath } from "./helpers/pristine.mjs";

const REL = "node_modules/@paperclipai/server/dist/routes/agents.js";
const ROUTE = 'router.post("/companies/:companyId/adapters/:type/test-environment"';
const scratch = fs.mkdtempSync(path.join(process.env.HARDENING_TEST_SCRATCH ?? os.tmpdir(), "patch-0027-"));
test.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
const VERSIONS = ["1005", "1012"].filter((v) => pristineOrNull(stockTreePath(v), REL));
const skip = VERSIONS.length ? false : noPristineSkip(stockTreePath("1012"), [REL], "1012");

/** routes/agents.js as the engine builds it from the pristine file with every patch of the package that changes it (0027 optional). */
function build(vkey, { with0027 }) {
  const found = discoverPatchFiles(SOURCE_PATCHES_DIR);
  const steps = [...found.keys()].filter((id) => PATCHES[id] && readPatchTarget(found.get(id)[0].file) === REL && (with0027 || id !== "0027"))
    .filter((id) => !(PATCHES[id].notNeededOn ?? []).includes(vkey)).sort(comparePatchIds)
    .map((id) => ({ id, marker: PATCHES[id].marker, candidates: orderCandidates(found.get(id), vkey) }));
  const r = buildFile({ rel: REL, pristine: pristineOrNull(stockTreePath(vkey), REL), steps, tmpDir: scratch });
  assert.equal(r.ok, true, r.reason);
  return r.content.toString("utf8");
}

/** Run the head of the test-environment handler: returns what happened for an actor of `type`. */
async function runHandlerHead(source, actorType) {
  const start = source.indexOf(ROUTE);
  assert.ok(start > 0, "the route is in the file");
  const authCall = source.indexOf("await assertCanCreateAgentsForCompany(req, companyId);", start);
  assert.ok(authCall > start && authCall - start < 3000, "the authorization call follows the route line closely");
  const head = source.slice(start, authCall + "await assertCanCreateAgentsForCompany(req, companyId);".length);
  const calls = { authorized: 0, logged: [] };
  let handler = null;
  const router = { post: (_path, _validate, fn) => { handler = fn; } };
  class HttpError extends Error { constructor(status, message, details) { super(message); this.status = status; this.details = details; } }
  // eslint-disable-next-line no-new-func
  const register = new Function("router", "validate", "testAdapterEnvironmentSchema", "assertKnownAdapterType", "assertCanCreateAgentsForCompany", "logger", "forbidden",
    `${head}\n    throw new Error("REACHED_AUTHORIZATION");\n});`);
  register(router, (x) => x, {}, (t) => t, async () => { calls.authorized += 1; }, { warn: (...a) => calls.logged.push(a) }, (message, details) => new HttpError(403, message, details));
  try {
    await handler({ params: { companyId: "c1", type: "claude_local" }, body: {}, actor: { type: actorType, agentId: actorType === "agent" ? "a1" : undefined, runId: "r1" } }, {});
    return { outcome: "returned", calls };
  } catch (e) {
    return { outcome: e.message === "REACHED_AUTHORIZATION" ? "reached-authorization" : e.status === 403 ? "forbidden" : `error: ${e.message}`, error: e, calls };
  }
}

for (const vkey of VERSIONS) {
  test(`${vkey}: an agent cannot start a Test environment probe (403, logged); a board user still reaches the authorization (fail-before: the agent does)`, { skip }, async () => {
    const patched = build(vkey, { with0027: true });
    assert.ok(patched.includes("// LOCAL-PATCH 0027"));
    for (const actor of ["agent", "none"]) {
      const r = await runHandlerHead(patched, actor);
      assert.equal(r.outcome, "forbidden", `${actor}: ${r.outcome}`);
      assert.equal(r.error.details.code, "adapter_test_board_only");
      assert.equal(r.calls.authorized, 0, "refused before any authorization or probe");
    }
    const agent = await runHandlerHead(patched, "agent");
    assert.equal(agent.calls.logged.length, 1);
    assert.equal(agent.calls.logged[0][0].event, "adapter_test_environment_denied");
    assert.equal(agent.calls.logged[0][0].agentId, "a1");
    const board = await runHandlerHead(patched, "board");
    assert.equal(board.outcome, "reached-authorization", "a board user goes on to the stock checks");
    assert.equal(board.calls.authorized, 1);

    const stock = build(vkey, { with0027: false });
    assert.ok(!stock.includes("LOCAL-PATCH 0027"));
    const before = await runHandlerHead(stock, "agent");
    assert.equal(before.outcome, "reached-authorization", "fail-before: an agent with the create-agents right got through to the probes");
    assert.equal(before.calls.authorized, 1);
  });
}
