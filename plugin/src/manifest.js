// Manifest per PaperclipPluginManifestV1 (@paperclipai/shared `pluginManifestV1Schema`). Capabilities and why (least
// privilege; nothing else is requested):
//   companies.read       iterate companies (compliance job, caps job, the Agent boxes company picker)
//   agents.read          read each agent's adapter config, permissions and status (boxes page, compliance, caps)
//   agents.pause         daily token caps: pause an agent over its cap, as the plugin itself
//   agents.resume        daily token caps: resume, at the next UTC day, only the agents the caps paused
//   issue.comments.create  daily token caps: one status comment per event (and the daily summary) on the status issue
//                        each company configures (as the plugin; plugin comments wake nobody)
//   authorization.grants.read  show tasks:assign / pipelines:write per agent and enforce "public web XOR tasks:assign"
//                        (READ ONLY: the plugin never sets grants; granting stays board-only)
//   database.namespace.read  read public.heartbeat_runs (the only core table declared below) for each run's token
//                        usage; the SDK has no heartbeat-run client. Paperclip requires a migrations folder and
//   database.namespace.migrate  this capability whenever `database` is declared; the folder is empty, the plugin's
//                        own schema stays unused and nothing is ever written
//   jobs.schedule        periodic compliance verification, the 5-minute daily token caps job, the 10-minute
//                        watchdog heartbeat check and the 10-minute alert tamper re-check
//   activity.log.write   an entry for every applied change, restore, settings change, restart request, box and cap
//                        change, failed self-test, watchdog enrolment and alert, and "drift detected" entries when the
//                        set of non-compliant agents changes
//   issues.create        alert issues, created as the plugin in the configured alert company/project and assigned to
//                        nobody (so they wake no agent): watchdog alerts, a failed self-test, a silent watchdog, and
//                        a "[RE-RAISED]" alert when a non-owner closed one (instead of reopening, so no issues.update)
//   issues.read          alert tamper re-check (src/recheck.js): read the status of the plugin's OWN alert issues
//                        (ctx.issues.get by the remembered id, for alertRecheckDays after each alert); nothing else
//   events.subscribe     alert tamper re-check: the "issue.updated" event is the only SDK source of WHO changed an
//                        issue (actorType/actorId of the host's activity entry); the SDK cannot read the activity log
//                        and the issue has no updatedBy field. Only close events of tracked alert issues are stored
//   webhooks.receive     the "watchdog" webhook (POST /api/plugins/paperclip-sandbox-hardening/webhooks/watchdog):
//                        enrolment with a one-time code, then heartbeats and alerts signed with the watchdog's own
//                        Ed25519 key (src/hostinstall.js); every unsigned or wrongly signed delivery is refused
//   plugin.state.read/write  the install-wide site settings and caps template (scope "instance"), per-company box
//                        settings, caps and usage snapshots, and the caps job state
//   ui.page.register     the "Hardening" and "Agent boxes" pages
// Not requested: agents.invoke/managed, authorization.grants.write, issues.update, activity.read (no SDK method uses
// it), http.outbound,
// secrets.*, local.folders. NOT AVAILABLE in the SDK: changing an agent's adapterConfig (no agents.update), so box
// edits are stored by the plugin and shown as a PATCH to apply by hand (src/boxes.js). Rebuilding Paperclip's files,
// the restart, reading run-log files and the Hermes state.db use plain Node fs/child_process in the worker process,
// which Paperclip does not gate by capability (see docs/PLUGIN-PLAN.md section 5, "Platform").
// Config (company-scoped in Paperclip; only instance admins can save it): adminUserIds gates every write action of
// both pages (see src/hardening.js); the next two are exceptions for the compliance job; alertOwnerUserIds and
// alertRecheckDays drive the alert tamper re-check (read from the config of the alert issue's company). Install-wide site values
// (allowlist, read-only paths, workspace roots, Hermes wrapper, restart unit, alert target) are edited on the
// Hardening page; boxes and caps on the Agent boxes page.
const manifest = {
  id: "paperclip-sandbox-hardening",
  apiVersion: 1,
  version: "0.1.0",
  displayName: "Sandbox hardening",
  description: "Switches the sandbox protections on and off (each one rebuilt from Paperclip's original files, one restart per save), keeps the site values in one settings file, and verifies every agent's sandbox configuration.",
  author: "<copyright holder>",
  categories: ["automation"],
  minimumHostVersion: "2026.1005.0",
  capabilities: [
    "companies.read", "agents.read", "agents.pause", "agents.resume", "issue.comments.create", "authorization.grants.read",
    "database.namespace.read", "database.namespace.migrate", "jobs.schedule", "activity.log.write", "plugin.state.read",
    "plugin.state.write", "ui.page.register", "issues.create", "webhooks.receive", "issues.read", "events.subscribe",
  ],
  entrypoints: { worker: "./src/worker.js", ui: "./src/ui.js" },
  database: { migrationsDir: "./src/migrations", coreReadTables: ["heartbeat_runs"] },
  instanceConfigSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      adminUserIds: {
        type: "array", items: { type: "string" }, default: [],
        title: "Users who may change protections (user ids)",
        description: "Instance admins listed here may use the switches, restart and restore on the Hardening page, and change boxes and caps (any company) on the Agent boxes page (both pages show your user id). Only instance admins can edit this list."
      },
      openNetworkAgentNames: {
        type: "array", items: { type: "string" }, default: [],
        title: "Agent names that are intentionally allowed open network (no allowlist)",
        description: "Everything else must have networkScope=allowlist."
      },
      canCreateAgentsAllowed: {
        type: "array", items: { type: "string" }, default: [],
        title: "Agent names that may hold canCreateAgents",
        description: "Everything else must not."
      },
      alertOwnerUserIds: {
        type: "array", items: { type: "string" }, default: [],
        title: "Users who may close alert issues (user ids)",
        description: "Only these users may close (done or cancel) the plugin's alert issues. If anyone else (an agent, another user) closes, cancels or deletes one within the re-check days, the plugin raises it again as a HIGH alert naming who closed it. Empty: the users in \"Users who may change protections\"."
      },
      alertRecheckDays: {
        type: "integer", minimum: 0, maximum: 90, default: 7,
        title: "Alert re-check days",
        description: "For how many days after an alert was raised the plugin checks who closed it. 0 turns the re-check off."
      }
    }
  },
  jobs: [
    { jobKey: "verify-sandbox-config", displayName: "Verify sandbox configuration", description: "Checks every agent against the hardening baseline and logs drift.", schedule: "*/15 * * * *" },
    { jobKey: "daily-token-caps", displayName: "Daily token caps", description: "Counts each agent's tokens today, pauses agents over their cap or company cap, resumes them at the next UTC day.", schedule: "*/5 * * * *" },
    { jobKey: "watchdog-heartbeat", displayName: "Watchdog heartbeat check", description: "Raises one alert when the enrolled watchdog has not reported in for more than 30 minutes.", schedule: "*/10 * * * *" },
    { jobKey: "alert-recheck", displayName: "Alert tamper re-check", description: "Re-raises, as a HIGH alert naming who did it, any recent alert issue of this plugin that someone other than an alert owner closed, cancelled or deleted.", schedule: "*/10 * * * *" }
  ],
  webhooks: [
    { endpointKey: "watchdog", displayName: "Watchdog reports", description: "Enrolment (one-time code), heartbeats and alerts from the host watchdog, each signed with its enrolled Ed25519 key." }
  ],
  ui: {
    slots: [
      { type: "page", id: "hardening-page", displayName: "Hardening", exportName: "HardeningPage", routePath: "hardening" },
      { type: "page", id: "agent-boxes-page", displayName: "Agent boxes", exportName: "AgentBoxesPage", routePath: "agent-boxes" }
    ]
  }
};
export default manifest;
