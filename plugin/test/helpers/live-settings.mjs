// The site values of the live (hand-patched) install, read back from its own patch blocks, so the tests can compare
// the package patches with the live ones without any site value being stored in this package.
import fs from "node:fs";
import path from "node:path";
import { blockFromPatchFile, evalBlock } from "../../src/patch-block.js";

const P0003 = "0003-spawn-time-sandbox-enforcement.patch";
const P0005A = ["0005a-new-agent-safe-defaults.1012.patch", "0005a-new-agent-safe-defaults.patch"];
const list = (s) => (s ? String(s).split(",").filter(Boolean) : []);

export function haveLiveSettings(liveDir) {
  return fs.existsSync(path.join(liveDir, P0003)) && P0005A.some((f) => fs.existsSync(path.join(liveDir, f)));
}

// Returns a settings object in the plugin's own format (what normalizeSettings accepts).
export function liveSettings(liveDir) {
  const file = P0005A.map((f) => path.join(liveDir, f)).find((f) => fs.existsSync(f));
  const b5 = evalBlock(blockFromPatchFile(file, "0005a"), "0005a", { env: {} });
  const b3 = evalBlock(blockFromPatchFile(path.join(liveDir, P0003), "0003"), "0003", { env: {} });
  const d = b5.NEW_AGENT_SAFE_DEFAULTS;
  return {
    workspaceRoots: b3.SANDBOX_WORKSPACE_ROOTS,
    baseAllowlist: d.networkAllowlist,
    extraReadOnlyPaths: d.filesystemExtraPaths,
    hermesWrapperPath: d.hermesCommand,
    hermesAllowlist: list(d.hermesSandboxAllow),
    hermesReadOnlyPaths: list(d.hermesSandboxRo),
  };
}
