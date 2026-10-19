// Lets `node --test plugin/test/` work on Node 22+, where a directory argument is run as a module (resolved to this
// file) instead of being searched for tests. When a test runner picks this file up by name (Node 20 directory search,
// default discovery), the test files run on their own, so nothing is imported twice.
import path from "node:path";

if (path.basename(process.argv[1] ?? "") !== "index.js") {
  for (const f of ["plugin.test.js", "settings.test.mjs", "patched-config.test.mjs", "engine.test.mjs", "worker.test.mjs", "boxes.test.mjs", "caps.test.mjs", "selftest.test.mjs", "hostinstall.test.mjs", "package.test.mjs"]) await import(`./${f}`);
}
