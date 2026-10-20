// Validates src/manifest.js against the host's own schema from @paperclipai/shared (must be installed).
import { pluginManifestV1Schema } from "@paperclipai/shared";
import manifest from "../src/manifest.js";
const r = pluginManifestV1Schema.safeParse(manifest);
if (!r.success) { console.error(JSON.stringify(r.error.issues, null, 2)); process.exit(1); }
console.log("manifest OK:", manifest.id, manifest.version, "capabilities:", manifest.capabilities.join(", "));
