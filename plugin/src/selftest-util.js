// Helpers shared by the self-test checks (selftest.js and selftest-box.js): where the patched files are, how to import a built
// module by content, how to evaluate a patch block cut out of a built file.
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { sha256 } from "./engine/store.js";
import { extractBlock, evalBlock } from "./patch-block.js";

export const SANDBOX_FILE = "node_modules/@paperclipai/adapter-utils/dist/local-process-sandbox.js";
export const SERVER_UTILS_FILE = "node_modules/@paperclipai/adapter-utils/dist/server-utils.js";
export const HEARTBEAT_FILE = "node_modules/@paperclipai/server/dist/services/heartbeat.js";
export const AGENTS_FILE = "node_modules/@paperclipai/server/dist/services/agents.js";
export const CLAUDE_EXECUTE_FILE = "node_modules/@paperclipai/adapter-claude-local/dist/server/execute.js";
export const OPENCODE_EXECUTE_FILE = "node_modules/@paperclipai/adapter-opencode-local/dist/server/execute.js";

/** Import a built module by content: the same content is imported once, a changed file gets a fresh instance. */
export async function importBuilt(tree, rel) {
  const file = path.join(tree, rel);
  const sha = sha256(fs.readFileSync(file));
  return import(`${pathToFileURL(file).href}?selftest=${sha}`);
}

export function evalBuiltBlock(tree, rel, id, opts) {
  return evalBlock(extractBlock(fs.readFileSync(path.join(tree, rel), "utf8"), id), id, opts);
}

export const expectThrow = (fn) => { try { fn(); return false; } catch { return true; } };
