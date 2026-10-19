// Packaging: the engine needs the patch files, which live in the package's host/patches (one source of truth, shared
// with apply.sh). `npm pack` / `npm publish` run this as prepack to copy them into plugin/patches (the engine prefers
// that folder when it exists), and as postpack with --clean to remove the copy again so it can never go stale.
//   node scripts/copy-patches.mjs [destDir]     copy ../host/patches/*.patch (default dest: <plugin>/patches)
//   node scripts/copy-patches.mjs --clean       remove <plugin>/patches
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PLUGIN = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SOURCE = path.resolve(PLUGIN, "../host/patches");
const arg = process.argv[2];
const dest = arg && arg !== "--clean" ? path.resolve(arg) : path.join(PLUGIN, "patches");

if (arg === "--clean") {
  fs.rmSync(dest, { recursive: true, force: true });
} else {
  const names = fs.readdirSync(SOURCE).filter((n) => n.endsWith(".patch")).sort();
  if (!names.length) throw new Error(`no patch files in ${SOURCE}`);
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  for (const n of names) fs.copyFileSync(path.join(SOURCE, n), path.join(dest, n));
  console.log(`copied ${names.length} patch files to ${dest}`);
}
