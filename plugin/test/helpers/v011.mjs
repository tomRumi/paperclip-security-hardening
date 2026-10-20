// The v0.1.1 release as it was installed: its engine (plugin/src/engine) and its patch files, read back from the release tag
// (or any git ref) into a scratch folder. Tests that upgrade from a v0.1.1 state use this engine to make the state, so the state is
// the one a real v0.1.1 install left, not one this package imitates. Skipped, with the reason, where git or the tag is missing.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
export const V011_REF = "v0.1.1";
/** The protections of the v0.1.1 release that are switched on by default. */
export const V011_DEFAULTS = Object.freeze(["sandbox-compat", "own-box", "only-boxed", "safe-defaults", "no-permission-handing", "pipeline-board-only", "assign-needs-grant", "public-web", "own-claude-folder"]);

/** {dir, enginePath, patchesDir} or {skip: reason}. The caller removes `dir` (or leaves it to the OS). */
export function v011Package(ref = V011_REF) {
  const git = (...args) => spawnSync("git", ["-C", REPO, ...args], { encoding: "utf8" });
  if (git("cat-file", "-e", `${ref}^{commit}`).status !== 0) return { skip: `no ${ref} release in this git history (no upgrade test)` };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "engine-v011-"));
  const tar = spawnSync("sh", ["-c", `git -C '${REPO}' archive ${ref} plugin/src/engine host/patches | tar -x -C '${dir}'`], { encoding: "utf8" });
  if (tar.status !== 0) { fs.rmSync(dir, { recursive: true, force: true }); return { skip: `cannot read the ${ref} package from git: ${tar.stderr}` }; }
  fs.writeFileSync(path.join(dir, "plugin/package.json"), '{"type":"module"}\n');
  return { dir, enginePath: path.join(dir, "plugin/src/engine/index.js"), patchesDir: path.join(dir, "host/patches") };
}

/** The v0.1.1 engine module (a fresh instance per `tag`, so two cases never share state). */
export const importV011Engine = (pkg, tag = "") => import(`${pathToFileURL(pkg.enginePath).href}?v011=${tag}`);
