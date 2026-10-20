// Where the tests get Paperclip's ORIGINAL bytes of a file, and which install they read them from. One helper for every test
// (engine, worker, instance-targeting, selftest, patch-00NN, the adapter harness), so none of them can disagree about it.
//
//   pristineOrNull(root, rel)   the original bytes of <root>/<rel> (a Buffer) or null. Tried in this order:
//                                1. <root>/<rel>.orig               the backup apply.sh keeps next to a file it patched
//                                2. <root>/<rel> itself             when it carries no "LOCAL-PATCH " marker (never patched)
//                                3. the engine store's pristine copy <engine data dir>/pristine/<rel>, when it carries no marker
//                                   (the engine keeps no .orig: once it has patched a file, step 2 fails and this one answers)
//                               The engine data dirs searched are `storeDirs` (default: $PAPERCLIP_HARDENING_ENGINE_DATA, then
//                               ~/.paperclip/sandbox-hardening). A file that only exists patched and has no stored original
//                               gives null, never the patched bytes.
//   pristineSource(root, rel)   the same as {bytes, source: "orig"|"unpatched"|"engine-store"} or null (for messages).
//   missingPristine(root, rels) the rels with no original, for a skip message.
//   stockTreePath(vkey)         the install the tests read: $PAPERCLIP_STOCK_TREE_<vkey> (for example PAPERCLIP_STOCK_TREE_1012),
//                               else ~/.paperclip/cli/installs/npm/2026.<vkey>.0. Point it at an untouched install (or one
//                               whose files still have .orig backups). Tests only ever READ it; they build scratch trees from
//                               it and never write into it or into the tree a running server uses.
//   stockTreeOrNull(vkey)       that install's tree root when it holds node_modules/@paperclipai, else null.
//   noPristineSkip(root, rels, vkey)  the loud skip text for the first missing original (names the file, what was tried and
//                               the variable to set). Tests that cannot find a pristine skip with this text; never silently.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const FOREIGN_MARKER = "LOCAL-PATCH ";

export function stockTreePath(vkey, env = process.env) {
  return env[`PAPERCLIP_STOCK_TREE_${vkey}`] || path.join(os.homedir(), ".paperclip", "cli", "installs", "npm", `2026.${vkey}.0`);
}

export function stockTreeOrNull(vkey = "1012", env = process.env) {
  const root = stockTreePath(vkey, env);
  try { return fs.statSync(path.join(root, "node_modules", "@paperclipai")).isDirectory() ? fs.realpathSync(root) : null; } catch { return null; }
}

export function defaultStoreDirs(env = process.env) {
  return [env.PAPERCLIP_HARDENING_ENGINE_DATA, path.join(os.homedir(), ".paperclip", "sandbox-hardening")].filter(Boolean);
}

const read = (file) => { try { return fs.readFileSync(file); } catch { return null; } };
const unmarked = (bytes) => bytes && !bytes.includes(FOREIGN_MARKER);

export function pristineSource(root, rel, { storeDirs = defaultStoreDirs() } = {}) {
  const orig = read(path.join(root, `${rel}.orig`));
  if (orig) return { bytes: orig, source: "orig" };
  const file = read(path.join(root, rel));
  if (unmarked(file)) return { bytes: file, source: "unpatched" };
  for (const dir of storeDirs) {
    const stored = read(path.join(dir, "pristine", rel));
    if (unmarked(stored)) return { bytes: stored, source: "engine-store" };
  }
  return null;
}

export const pristineOrNull = (root, rel, options) => pristineSource(root, rel, options)?.bytes ?? null;

export const missingPristine = (root, rels, options) => [...rels].filter((rel) => !pristineOrNull(root, rel, options));

export function noPristineSkip(root, rels, vkey = "1012", options) {
  const missing = missingPristine(root, rels, options);
  if (!missing.length) return false;
  return `NO PRISTINE: ${missing.length} patched file(s) have no original in ${root} (first: ${missing[0]}; tried ${missing[0]}.orig, the file itself when unpatched, `
    + `the engine store ${(options?.storeDirs ?? defaultStoreDirs()).map((d) => path.join(d, "pristine")).join(" or ")}); set PAPERCLIP_STOCK_TREE_${vkey} to an untouched Paperclip 2026.${vkey}.0 install`;
}
