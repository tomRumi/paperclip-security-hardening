// The self-contained code blocks that patches 0003 (heartbeat.js) and 0005a (services/agents.js) add: cut the block out
// of a patch file (its added lines) or out of a built Paperclip file, and evaluate it with stubs for the few
// module-level names it uses. Used by the self-test (src/selftest.js, on the built files) and by the tests.
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

const HUNK = "//@@ hunk";

export const BLOCKS = {
  "0003": { start: "// LOCAL-PATCH 0003: spawn-time", end: /^const SESSIONED_LOCAL_ADAPTERS\b/, exports: ["SANDBOX_WORKSPACE_ROOTS", "enforceStoredSandboxConfig"] },
  "0005a": { start: "// LOCAL-PATCH 0005a: safe defaults", end: /^function buildConfigSnapshot\b/, exports: ["NEW_AGENT_SAFE_DEFAULTS", "applyNewAgentSafeDefaults"] },
};

/** The code a unified diff adds (its "+" lines), hunks separated by a marker line. */
export function addedText(patchText) {
  const out = [];
  for (const line of patchText.split("\n")) {
    if (line.startsWith("@@")) out.push(HUNK);
    else if (line.startsWith("+") && !line.startsWith("+++")) out.push(line.slice(1));
  }
  return out.join("\n");
}

/** Lines from the one containing `start` up to (not including) the first that matches `end` or is a hunk marker. */
export function extractBlock(text, id) {
  const { start, end } = BLOCKS[id];
  const lines = text.split("\n");
  const from = lines.findIndex((l) => l.includes(start));
  if (from < 0) throw new Error(`block ${id} not found`);
  let to = lines.findIndex((l, i) => i > from && (l === HUNK || end.test(l)));
  if (to < 0) to = lines.length;
  return lines.slice(from, to).join("\n");
}

/** The file without block `id` and without the import lines tagged `// LOCAL-PATCH <id>` (everything else must match). */
export function withoutBlock(text, id) {
  const block = extractBlock(text, id);
  return text.replace(block, "").split("\n").filter((l) => !(l.startsWith("import ") && l.endsWith(`// LOCAL-PATCH ${id}`))).join("\n");
}

/**
 * Evaluate block `id` (text from extractBlock) and return its exported names.
 * @param {object} o  env: the process environment the block sees; instanceRoot: what resolvePaperclipInstanceRoot() returns
 */
export function evalBlock(code, id, { env = {}, instanceRoot = "/nonexistent-instance-root" } = {}) {
  const warnings = [];
  const logger = { warn: (obj, msg) => warnings.push({ obj, msg }), info() {}, error() {}, debug() {} };
  const isPlainRecord = (v) => typeof v === "object" && v !== null && !Array.isArray(v);
  const scope = {
    process: { env },
    path,
    fs: fsp,
    logger,
    parseObject: (v) => (isPlainRecord(v) ? v : {}),
    isPlainRecord,
    readHardeningConfigFile: fs.readFileSync,
    hardeningInstanceRoot: () => instanceRoot,
  };
  const names = BLOCKS[id].exports;
  // eslint-disable-next-line no-new-func
  const fn = new Function(...Object.keys(scope), `"use strict";\n${code}\nreturn { ${names.join(", ")} };`);
  return { ...fn(...Object.values(scope)), warnings };
}

export function blockFromPatchFile(file, id) {
  return extractBlock(addedText(fs.readFileSync(file, "utf8")), id);
}
