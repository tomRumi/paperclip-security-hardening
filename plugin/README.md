# Paperclip plugin: Sandbox hardening

One switch per sandbox protection, Agent boxes with daily token caps, a self-test after every restart, and one-line installs for the
watchdog and the Hermes wrapper. What it protects, the assumptions, the switch table, the install lines and the known limits are in the
[root README](../README.md); the design is in [docs/PLUGIN-PLAN.md](../docs/PLUGIN-PLAN.md).

* **Hardening page** (admin only): switches with dependencies, Save shows the plan, the affected Paperclip files are rebuilt from their
  originals plus the switched-on protections (`src/engine`, all-or-nothing), then one restart. "Restore originals" puts every original
  back. On every worker start the switched-on set is rebuilt against the current files (no version lock; a protection whose target
  code changed shows "unavailable on this install"). A self-test checks each applied protection after the restart.
* **Agent boxes page:** one row per existing agent with its box and daily cap (default, per-agent override, company cap, new-company
  template). The SDK cannot update agents, so a box change is shown as a `PATCH` for an admin to apply.
* **Who can change things:** plugin actions are callable by company members and agents, and the plugin is told who calls but not
  whether they are an instance admin. Write actions refuse agents and accept a user only when an instance admin listed their user id
  in the setting "Users who may change protections" (the page shows your id). See `src/hardening.js`.
* **Site values** (base allowlist, read-only paths, workspace roots, Hermes wrapper, restart unit, alert target) are set on the Hardening
  page. The plugin writes the part Paperclip needs to `$PAPERCLIP_HARDENING_CONFIG`, else `<instance root>/hardening/config.json`;
  patches 0003 and 0005a read it at startup and fall back to secure generic defaults. See `src/settings.js`.
* **Install:** through Paperclip's plugin installer (`paperclipai plugin install paperclip-sandbox-hardening`, or a path to this
  directory); enable; review the permissions card.
* **Packaging:** the patch files stay in the package's `host/patches` (one copy, shared with `apply.sh`). `npm pack` / `npm publish` copy
  them into `plugin/patches` (prepack) and remove the copy afterwards (postpack); the engine uses `plugin/patches` when present, else
  `../host/patches` (git checkout or local-path install).
* **Check:** `npm run validate-manifest` (needs `@paperclipai/shared` installed) and `npm test`. Tests that compare against a live
  Paperclip install copy only the target files from its `.orig` backups into a scratch dir and skip without it
  (`HARDENING_LIVE_PATCHES`, `PAPERCLIP_TREE`; `HARDENING_TEST_SCRATCH` sets the scratch parent).
* **Fallback without the plugin:** `node bin/hardening-engine.mjs status|plan|apply|restore` (see `src/engine/README.md`).
