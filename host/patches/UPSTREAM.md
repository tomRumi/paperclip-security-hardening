# Upstream PR notes (paperclipai/paperclip, MIT)

The patches are against the published `dist` JS of Paperclip (2026.1005.0 and 2026.1012.0 were checked; variants `*.1012.patch` exist where the
code differs). Upstream is TypeScript, so a PR needs the same change in `src`. The plugin's engine does not pin a version: a patch is used wherever
it fits the file, and a protection whose target code changed shows "unavailable on this install". Accepted upstream changes drop out of the package.

Site values (workspace roots, base allowlist, read-only paths, Hermes wrapper) are not hard-coded in the patches. Patches 0003, 0003b and 0005a read them once at
startup (0005f re-reads only `remoteExceptions`, with the same trust checks, each time such an agent is about to run) from the hardening settings file: `$PAPERCLIP_HARDENING_CONFIG`, else `<instance root>/hardening/config.json` (the plugin writes it). They ignore the file (secure generic defaults, one `sandbox_enforcement` warning) unless its real path is outside
`<instance root>/workspaces`, `/projects`, `/companies` and every workspace root, it is a 0600 file owned by the service user, and its directory is owned by that
user and not group- or world-writable. Without the file they use secure generic defaults. For 0003 only, `PAPERCLIP_SANDBOX_WORKSPACE_ROOT` is still honoured when the file sets no roots.

## Patch set 0001-0027

| Patch | Target | Purpose |
|---|---|---|
| 0001 | adapter-utils `local-process-sandbox` | Sandbox starts on usr-merged hosts (no bind onto the `/bin`, `/lib` symlinks bwrap creates) |
| 0002 | server `routes/agents` | Agents cannot change sandbox, network, command, instructions or skills keys of an agent (board-only) |
| 0003 | server `services/heartbeat` | Forces the stored sandbox config at every spawn; drops launch-changing env; refuses workspaces outside the allowed roots |
| 0003b | server `services/heartbeat` | More spawn-time enforcement: the engine, the state and config redirects and the Paperclip endpoint variables of a run are dropped or reset; a boxed Hermes agent is enforced too; publishes the workspace roots for the box helper |
| 0004 | adapter-utils `local-process-sandbox` | Allowlist proxy survives a client reset (EPIPE) instead of taking the server down |
| 0005a | server `services/agents` | New agents (create, hire, import, join) start boxed with a per-type table (CLI engine where the type has an ACP engine, the type's allowlist, no create-agent or create-skill right); env names that redirect the box are removed |
| 0005b | server `services/heartbeat` | Fail closed: an agent without a sandbox (or a Hermes agent without the wrapper) is refused at spawn |
| 0005c | server `routes/agents` | New agents get no default task-assign grant |
| 0005d | server `services/company-portability` | Same for agents created by company import |
| 0005e | server `services/agent-permissions` | New agents get no default grants (variant for 1012) |
| 0005f | server `services/heartbeat` | Table-driven admission (replaces the claude/hermes-only rule of 0005b): scoped types need the full box, remote types an admin exception, everything else is refused |
| 0006a | server `services/heartbeat` | Git worktrees: the repository's common dir is mounted for the run (spawn side) |
| 0006b | adapter-utils `local-process-sandbox` | Git worktrees: hooks, config and info of the common dir stay read-only (sandbox side) |
| 0007 | server `routes/pipelines` | Pipeline structure (stages) is board-only; agents may still move work along |
| 0008 | server `services/agents` | A stored or echoed `***REDACTED***` value can never overwrite real adapter config |
| 0009 | server `routes/agents` | Granting or changing agent permissions is board-only |
| 0010 | server `services/built-in-agents` | The startup sync no longer hands the CEO agent change grants |
| 0011a | shared `validators/agent` | Adds the `canWritePipelines` flag to the permissions schema |
| 0011b | server `routes/agents` | The board-only permissions route also covers the pipelines-write flag |
| 0012 | adapter-utils `local-process-sandbox` | `NO_PROXY=localhost` in allowlist runs, so apps inside the run are reachable; host services stay behind the proxy |
| 0013a | server `services/authorization` | Assigning work to another agent or a user needs an explicit `tasks:assign` grant |
| 0013b | server `routes/agents` | The access display no longer reports a derived "simple default" assign right |
| 0014 | server `run-dispatch/adapters/postgres` | An "interaction pending" wake counts only while that interaction is still pending and addressed to the agent |
| 0015 | adapter-utils `local-process-sandbox` | `*:<port>` allowlist entry = any public host on that port, nothing local or private (the "public-web box") |
| 0016 | adapter-claude-local `execute` | Each boxed agent gets its own Claude config folder (settings, hooks, conversations) |
| 0017 | adapter-utils `local-process-sandbox` | The shared box helper for adapters (mount guard, trusted URLs, boxed-adapter registry) and a log line for every denied connection |
| 0019 | adapter-opencode-local `execute` | `opencode_local` runs in the box: own home and state folders per agent, skills copied in |
| 0019b | adapter-opencode-local `models` | `opencode models` (model discovery) runs in the box |
| 0019c | adapter-opencode-local `runtime-config` | A boxed run takes `{env:NAME}` values and its config only from the agent's own env, never the server's |
| 0019d | adapter-opencode-local `test` | The "Test environment" probes run in the box, and a local probe starts the server's own OpenCode, never the command of the request |
| 0025 | adapter-utils `server-utils` | A boxed child gets a fixed list of variables plus the names its adapter lists, not the server's environment |
| 0026 | adapter-claude-local `execute` | `claude_local` runs through the shared box helper and the environment scrub |
| 0026b | adapter-claude-local `test` | The "Test environment" probe of a local target always loads user settings only, runs in an empty folder (no project hooks) and ignores a `CLAUDE_CONFIG_DIR` that is not the managed AI connection's home |
| 0026c | adapter-claude-local `acp` | The same for the ACP probe |
| 0027 | server `routes/agents` | `POST /companies/:id/adapters/:type/test-environment` is for board users only (an agent with the create-agents right was enough before) |

In the plugin, the switches map to the patches as: Sandbox compatibility 0001, 0004, 0006a/b, 0012, 0014; own box 0002, 0003, 0003b, 0008; box Claude agents 0017, 0025, 0026, 0026b, 0026c;
box OpenCode agents 0019, 0019b, 0019c, 0019d (needs box Claude agents); only boxed agents 0005b, 0005f, 0027;
safe defaults 0005a, 0005c, 0005d, 0005e, 0010; no permission handing 0009, 0011a/b; pipeline 0007; assign grant 0013a/b; public-web box 0015; own Claude folder 0016.
Separate PRs are suggested per numbered section below (0014-0016 are described at the end).

## 1. Sandbox fails to start on usr-merged hosts (adapter-utils `local-process-sandbox`)

Patch: `0001-sandbox-usrmerge-mounts.patch`.

**Problem.** `buildLocalProcessSandboxSpawnTarget()` with `filesystemScope: "workspace"` first emits
`--symlink usr/bin /bin` (also `/sbin`, `/lib`, `/lib64`), then bind-mounts every entry of `SYSTEM_READ_PATHS`
(`/bin`, `/sbin`, `/usr`, `/lib`, `/lib64`, ...). On hosts where `/bin -> usr/bin` (Debian 12+, Ubuntu 20.04+, Fedora, Arch)
`--ro-bind /bin /bin` targets the symlink bwrap just created, and bwrap exits 1:

    bwrap: Can't bind mount /oldroot/usr/bin on /newroot/bin: Unable to mount source on destination: No such file or directory

So no agent with a workspace filesystem scope can start on a modern Linux host.

**Repro.** On a usr-merged Linux host with bwrap:
`buildLocalProcessSandboxSpawnTarget({ executable: "/usr/bin/bash", args: ["-c","echo hi"], cwd: ws, options: { filesystemScope: "workspace", workspaceDir: ws } })`,
then spawn `{command, args}`. Before the fix: exit 1 with the message above. After: exit 0.

**Fix (function level).** In `buildLocalProcessSandboxSpawnTarget`, inside the local `mount(source, access)` helper (so it also covers
`executableReadPaths()` results such as `/bin` for `/bin/bash`): return early when the normalized path is one of
`/bin`, `/sbin`, `/lib`, `/lib64` and the host path is a symlink whose realpath is under `/usr/`; the `--symlink` already provides it.
New module-level `USR_MERGE_SYMLINK_PATHS` set and small `isUsrMergeSymlink(path)` helper (`lstat` + `realpath`). Other symlinked
entries (`/etc/resolv.conf`, `/etc/localtime`) are unchanged: bwrap resolves a symlink *source* and binds the real target at the
original destination, so DNS config and timezone keep working (verified). On hosts where `/bin` is a real directory nothing changes.

**Test.** Unit test in `local-process-sandbox.test.ts`: stub `fs.lstat/realpath` (or run on a usr-merged CI image) and assert the
returned `args` contain `--symlink usr/bin /bin` and no `--ro-bind /bin /bin`; plus an integration test (skipped without bwrap)
that runs `bash -c 'getent hosts localhost; date'` in the workspace scope and expects exit 0, host `/tmp` writes not visible,
workspace writes visible. Verified manually: workspace scope exit 0, DNS and `date` work, `~/.claude/.credentials.json` unreadable,
host `/tmp` isolated; allowlist scope `[github.com]`: github.com reachable, example.com blocked.

## 2. Agent can switch off its own sandbox via `PATCH /agents/:id` (server `routes/agents`)

Patch: `0002-agent-self-config-change-grant.patch`.

**Problem.** `authorizationService.decide()` returns `allow_self` for `agent_config:update` on the actor's own agent unless
`scope.requiresChangeGrant` is set (`services/authorization.ts`, the `input.action === "agent_config:update" && resource.agentId === actorAgentId` branch).
`PATCH /agents/:id` does not set the scope for sandbox keys, and `POST /agents/:id/config-revisions/:revisionId/rollback` does not either. A sandboxed agent
holding its own API key can therefore clear `filesystemScope`, `networkScope`, `networkAllowlist`, `filesystemExtraPaths`, `filesystemSandboxCommand`, or change `command`,
`hermesCommand`, `env` on itself and escape the sandbox on its next run. (2026.1012.0 already forbids agent keys from setting `command`, `hermesCommand`, `args`,
`extraArgs`, `cwd`, `env`, `filesystemSandboxCommand` on `*_local` adapters via `assertNoAgentLocalAdapterHostCommandMutation`, but not the scope/allowlist/extra-path keys.)

**Repro.** With an agent API key: `PATCH /api/agents/<own id>` body `{"adapterConfig":{"filesystemScope":null,"networkScope":null}}`. Response 200; the next run is unsandboxed.

**Fix (function level).** Reuse the existing mechanism (`assertCanApplyProtectedAgentChange`, which calls `decide()` with `scope: { requiresChangeGrant: true }`
so the actor needs `agents:configure`). Add to `agentRoutes`:
- module constant `AGENT_EXECUTION_ADAPTER_CONFIG_KEYS`: `filesystemScope, networkScope, networkAllowlist, filesystemExtraPaths, filesystemSandboxCommand, command, hermesCommand,
  agentCommand, acpAgentCommand, args, extraArgs, env, cwd, workspaceDir, sandbox, dangerouslySkipPermissions, dangerouslyBypassApprovalsAndSandbox, dangerouslyBypassSandbox, yolo,
  approvalMode, permissionMode, acpPermissionMode, nonInteractivePermissions, acpNonInteractivePermissions, codexPermissionMode, opencodePermissionMode, acpxPermissionMode, chrome,
  workspaceStrategy, managedAiConnection` (what the process can reach, what it executes, with which environment, and whether permission prompts or the adapter's own sandbox are bypassed);
- `assertAgentActorMayChangeExecutionConfig(req, targetAgent, next)`: for agent actors only, compare the effective next config with the stored one for those keys, plus `adapterType` and `defaultEnvironmentId`;
  if any differs, `await assertCanApplyProtectedAgentChange(req, targetAgent, [])`. Empty target keys means the consent shortcut is not offered: the agent needs a direct `agents:configure` grant, otherwise 403
  "Missing permission: agents:configure or agents:suggest-changes.";
- call it in `PATCH /agents/:id` after the merged `patchData.adapterConfig` is computed (before `assertCanUpdateAgent`) and in the config-revision rollback handler before `svc.rollbackConfigRevision`.
  The rollback call also passes `defaultEnvironmentId` (as `configPatchFromSnapshot` restores it: a string, else null), so a rollback cannot swap the agent's environment either.
Board users and agents holding `agents:configure` are unaffected; unchanged values (an agent re-sending its config) and other keys (`model`, `timeoutSec`, ...) still use `allow_self`.
**Execution keys.** The key list also covers every `instructions*` key (`instructionsFilePath`, `instructionsRootPath`, `instructionsEntryFile`, `instructionsBundleMode`, `agentsMdPath`; keys of both the stored and the next config are compared). A change to any of them by an agent actor now gets 403 `execution_config_board_only` (warn `agent_execution_config_denied`) **even when the agent holds `agents:configure`**; the grant path is no longer consulted (see §10 for why that grant is not a safe gate). Instructions bundle writes are board-only for agent actors, own bundle included (`PATCH .../instructions-bundle`, file `PUT`/`DELETE`, `restore`, candidate `resolve`; 403 `instructions_write_board_only`): role instructions are managed by the board from files (push-bundle), and agent self-edit would let a prompt-injected agent persist instructions across runs (learning goes through memory). No agent 'propose' route exists (candidates are created by runs themselves; only resolving is blocked). Reads untouched. `promptTemplate` and `bootstrapPromptTemplate` are execution keys too (an agent editing its own prompt would persist across runs). `POST /agents/:id/skills/sync` is board-only for agent actors, self included (403 `skill_sync_board_only`; skills carry instructions). Related, in 0005a: new agents get `permissions.canCreateSkills=false` (upstream default true). Not changed: the check still compares the full merged next config, which is fail-closed. Original behaviour kept for non-execution keys (`model`, `timeoutSec`, ...): `allow_self`.

**Test.** Route/authorization tests: agent actor patching its own `filesystemScope` / `networkAllowlist` / `env` / `adapterType` and rolling back to an unsandboxed revision gets 403; patching `model` gets 200;
a board user gets 200; an agent with `agents:configure` gets 200. Verified with the real `decide()` and a stub db.
Possible follow-up: also guard agent hire/create (`POST /agents`, `/agent-hires`) so a new agent cannot be created without the creator's sandbox keys; and offer a `request_confirmation` consent target for these keys instead of a hard 403.

## 3. Per-run overrides can change what a sandboxed agent run reaches (server `services/heartbeat`)

Patch: `0003-spawn-time-sandbox-enforcement.patch`.

**Problem.** The effective run config is built from the agent's stored `adapterConfig`, then merged with `issue.assigneeAdapterOverrides.adapterConfig`,
project env, routine env and the project workspace `cwd` (`mergedConfig` -> `resolveExecutionRunAdapterConfig` -> `runtimeConfig` in `heartbeat`'s run executor).
Agents can write those inputs (issue create/update, project and routine env, project workspace cwd) with their own key, and none of them go through the
`agent_config:update` check of patch 0002. An agent can therefore clear `filesystemScope`/`networkScope`, widen `networkAllowlist`/`filesystemExtraPaths`,
point the workspace at `/home`, or set `LD_PRELOAD`/`NODE_OPTIONS`/`PATH` for the next run without ever editing its own agent record.

**Repro.** With an agent key on a sandboxed agent: `PATCH /api/issues/<id>` body `{"assigneeAdapterOverrides":{"adapterConfig":{"filesystemScope":null,"networkScope":null}}}`
on an issue assigned to that agent; the next run starts unsandboxed. Or set a project workspace `cwd` to `/home/<user>`.

**Fix (function level).** One enforcement point instead of guarding each write route: in the run executor, directly before `adapter.execute(...)`
(after `adapterContext` is built and `runtimeConfig` is final), call new module-level `enforceStoredSandboxConfig({ agent, runId, runtimeConfig, workspaceDirs, managedAi })`
for local targets. It does nothing unless the STORED `agent.adapterConfig` has `filesystemScope` or `networkScope`. Then it:
- restores every key of `SANDBOX_ENFORCED_ADAPTER_CONFIG_KEYS` (scopes, allowlist, extra paths, sandbox command, command/args, permission-bypass keys; plus `managedAiConnection`
  unless the server prepared a managed AI runtime) to the stored value, deleting keys the agent did not store;
- drops launch-changing env from the merged `env` unless it equals a stored plain value: `*SANDBOX*`, `BWRAP*`, `LD_*`/`DYLD_*`/`GLIBC_TUNABLES` (loader injection), `NODE_OPTIONS`/`NODE_PATH`,
  `BASH_ENV`/`ENV`, `HTTP(S)_PROXY`/`ALL_PROXY`/`NO_PROXY` (owned by the allowlist proxy), a `PATH` with entries outside `/usr /bin /sbin /lib /lib64 /opt /snap`,
  and `CLAUDE_CONFIG_DIR`/`CODEX_HOME`/`GROK_HOME` (they decide which credential directory is bound into the sandbox) unless a managed AI runtime set them;
- refuses the run (throws) if the execution/context workspace cwd, `config.cwd` or `config.workspaceDir` does not `realpath` into an allowed root. Roots:
  the `workspaceRoots` of the hardening settings file (`$PAPERCLIP_HARDENING_CONFIG`, else `<instance root>/hardening/config.json`), else `PAPERCLIP_SANDBOX_WORKSPACE_ROOT` (colon separated), else `<instance root>/workspaces` and `<instance root>/projects`; read once at startup; a missing directory is resolved through its nearest existing parent,
  a dangling symlink is refused;
- also restores the host file-path keys the server or adapters read into the prompt or launch (`instructionsFilePath`, `instructionsRootPath`, `instructionsEntryFile`, `instructionsBundleMode`, `workspaceStrategy`, `stateDir`, `acpStateDir`, `mcpConfigPath`) to the stored value, so an issue override cannot make the server read an arbitrary host file; note this also reverts a per-issue `workspaceStrategy` for sandboxed agents;
- logs one `warn` line per action (`event: "sandbox_enforcement"`, `restore_config_key` / `drop_env` / `refuse_run`).
Upstream could make the roots a per-company setting.

**Test.** Unit tests on `enforceStoredSandboxConfig` with a stub agent: override clearing scopes ends with the stored scopes; cwd `/home/<user>`, a symlink to it and `..` escapes are refused;
`LD_PRELOAD`/`NODE_OPTIONS`/`HTTPS_PROXY` dropped, system `PATH` kept; normal workspace passes unchanged with no log lines; an agent without a stored scope gets the same object back.

## 4. Allowlist proxy can take the server down on a client reset (adapter-utils `local-process-sandbox`)

Patch: `0004-sandbox-proxy-epipe.patch`.

**Problem.** `startNetworkAllowlistProxy()` runs inside the server process. In its `connect` handler the upgraded `clientSocket` has no `'error'` listener
(Node's http server removes its own listener for CONNECT sockets), and neither does the plain-HTTP `request`/`response` pair. When a sandboxed client resets or closes mid-tunnel while
`upstream.pipe(clientSocket)` is writing, the socket emits `EPIPE`/`ECONNRESET` with no handler, which is an uncaught exception; the Paperclip CLI exits on it, so every run in flight dies.

**Repro.** Start the proxy, `CONNECT` to an allowed host that streams data, destroy the client socket after the `200`: the process dies with `Error: write EPIPE`
(12 of 12 attempts in a reproduction script; seen intermittently in real runs).

**Fix (function level).** In `startNetworkAllowlistProxy`: `clientSocket.on("error", () => upstream.destroy())` in the `connect` handler; `request.on("error", ...)` and `response.on("error", ...)`
destroying the upstream request in the HTTP handler; `socket.on("error", () => socket.destroy())` in the `connection` handler that tracks sockets. A client error now closes that connection only.

**Test.** Integration test that opens N tunnels and resets them mid-stream, asserts no `uncaughtException`/`unhandledRejection` and that a following `CONNECT` still gets `200`.

## 5. New-agent safe defaults + fail closed at spawn (0005a, 0005b)

Patches: `0005a-new-agent-safe-defaults.patch` (server `services/agents.js`), `0005b-fail-closed-spawn.patch`
(server `services/heartbeat.js`, extends 0003). They are one logical change, split in two files only because
`apply.sh` handles one target file per patch.

**Problem.** (a) A new agent (direct create, agent-hires + approval, join request, built-in) got
`permissions.canCreateAgents=true` and no sandbox keys, so 0003 (which returns early when neither scope is stored)
let it run with no sandbox. (b) The hire approval payload stores the redacted display copy of the adapterConfig, so
`networkAllowlist` entries were persisted as the literal string `***REDACTED***`.

**0005a.** `create()` and `activatePendingApproval()` call `applyNewAgentSafeDefaults()`: `canCreateAgents=false`;
for `claude_local`: `engine=cli` (see below), `filesystemScope=workspace`, `filesystemSandboxCommand=/usr/bin/bwrap`, base
`filesystemExtraPaths` (the settings file's `extraReadOnlyPaths`, for example a credential broker's `/opt/vault/bin`), `networkScope=allowlist` with only the settings file's `baseAllowlist` (default `api.anthropic.com`); for `hermes_local`: `command` = the settings file's `hermesWrapperPath` (default `/usr/local/bin/hermes-sandbox`) and `env.HERMES_SANDBOX_ALLOW` (`hermesAllowlist`, default `openrouter.ai`; **no other model-provider host unless you configure one**) plus `env.HERMES_SANDBOX_RO` (`hermesReadOnlyPaths`, which must list the Hermes install directories). All of these come from the settings file, read once at startup (`$PAPERCLIP_HARDENING_CONFIG`, else `<instance root>/hardening/config.json`); an empty or missing value falls back to the secure default. The patch ignores creator-supplied
values for those keys (warn log `event=new_agent_defaults`); the table `NEW_AGENT_BOX_PROFILES` (equal to the plugin's `BOX_PROFILES`; a test compares them) gives every other scoped local type (v0.2.0: `codex_local`, `opencode_local`, `gemini_local`, `cursor`, `pi_local`, `kimi_local`, `grok_local`) the same scopes, its own allowlist (the `baseAllowlists[type]` setting, else the provider's own API hosts; for `opencode_local` the four common provider hosts `openrouter.ai`, `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`) and, where the type has an ACP engine, `engine=cli`; other types (remote, gateway, process) only get `canCreateAgents=false`. Constants live in the `NEW_AGENT_SAFE_DEFAULTS` block of
the patched server file (not agent-writable). Board PATCH (`updateAgent`) is untouched, so extra hosts are added later;
existing agents are not modified.

*Engine (claude_local).* The adapter's `engine` default is `auto`, which means ACP (`adapter-claude-local` `config-schema.js`: "Default (ACP)"; `acp.js` `normalizeEngine()` maps an unset, empty, `auto` or unknown value to ACP, not explicit). `resolveClaudeExecutionEngineForRun()` (`acp.js`, called from `execute.js` before anything is spawned) returns an `adapter_engine_unavailable` error for every non-`cli` selection when `filesystemScope` or `networkScope` is set: "Local filesystem/network confinement requires the Claude CLI engine; ACP confinement is not supported." Without the engine key, a new agent boxed by this patch would be refused at its first run. So `applyNewAgentSafeDefaults()` stores `engine=cli` for every new agent of a type with an ACP lane (`claude_local`, `codex_local`, `gemini_local`, `kimi_local`), **whatever the creator sent, an explicit `acp` or `cli` included** (v0.2.0; v0.1.1 kept an explicit value). The spawn-time enforcement (0003/0003b) restores a run's `engine` to the STORED value and the admission (0005f) requires the stored value to be `cli`, so a stored `acp` would be trusted for every later run, and the ACP lane never sees the box. The board can still change it later with a PATCH; an ACP boxed agent is then refused at run time with the message above (fail closed, never unboxed). Verified on 2026.1012.0 (`adapter-claude-local` 2026.1012.0, `dist/server/acp.js:19-46`, `execute.js:260-274`). The plugin's compliance check (`checkAgent`) does not flag the engine: an ACP boxed agent is a function problem, not a security gap; the ITSec check (`checkItsecAgent`) requires `cli`, as does the ITSec declaration.

*Creator-supplied env (v0.2.0).* The enforcement of 0003 lets a run's env value through when it equals the STORED plain value, so a value stored at creation stays trusted for every later run: a creator-supplied `CODEX_HOME=~/.codex`, `HERMES_SANDBOX_PASS=DATABASE_URL` or `HERMES_SANDBOX_HOME` would be honoured forever. `applyNewAgentSafeDefaults()` therefore removes, from the env of every new boxed agent (the scoped types and `hermes_local`), every name the enforcement would drop from a run: `*SANDBOX*` (all `HERMES_SANDBOX_*`), `BWRAP*`, loader and node injection (`LD_*`, `DYLD_*`, `GLIBC_TUNABLES`, `NODE_OPTIONS`, `NODE_PATH`), `BASH_ENV`, `ENV`, proxy variables, a `PATH` outside the system directories (or not a plain value), the state and credential-directory redirects (`HOME`, `HERMES_HOME`, `XDG_*`, `OPENCODE_*` except `OPENCODE_AUTH_JSON`, `GEMINI_CLI_HOME`, `PI_CODING_AGENT_DIR`, `KIMI_CODE_HOME`, `CURSOR_HOME`, `CURSOR_DATA_DIR`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `GROK_HOME`, `PAPERCLIP_*_PROVIDERS`) and the Paperclip endpoints the box trusts (`PAPERCLIP_API_URL`, `PAPERCLIP_RUNTIME_TOOLS_*`). Credentials (API keys, tokens, secret references under any other name) stay. The removed names (never the values) are listed in the `event=new_agent_defaults` warn log as `droppedEnv`. The two rules are copies in two files; a test compares what they flag over a list of names.

**0005b** (v0.1.x rule; since v0.2.0 the function body is replaced by 0005f, section 22). `refuseUnsandboxedLocalAgent()`, called right after the 0003 hook, refuses the run (error `Sandbox policy: run refused, ...`, warn log
`event=sandbox_enforcement action=refuse_unsandboxed`) for: `claude_local` without a stored
`filesystemScope` (the only adapter that implements it); `hermes_local` whose stored `command` is not
`/usr/local/bin/hermes-sandbox`; every other adapter type, `codex_local` included (no sandbox implementation exists for process, http,
opencode, ...). Applies to local execution targets only (the hook's existing condition).

**Per-version files and no default grants (0005a variants, 0005c, 0005d, 0005e).** `apply.sh` picks `X.<MMDD>.patch` over `X.patch`
(MMDD = second field of the server version): 0005a for 2026.1005.0 is `0005a-...patch`, for 2026.1012.0 `0005a-...1012.patch` (only the import hunk differs: 1012
reorders imports; also adds `logger` import). An entry is skipped for a missing file only if its 5th field lists that vkey (0005e: `1005`); any other version, or an unparseable version, makes `apply.sh` fail with nothing changed.

*Problem (1012, B1).* Every new non-built-in, non-low-trust agent got `NEW_STANDARD_AGENT_DEFAULT_GRANT_KEYS` (`agents:configure`, `agents:suggest-changes`,
`skills:create`, `skills:suggest-changes`, `tools:manage_connections`, `tools:manage_profiles`, `tools:view_audit`, `audit:view_agent_actions`, `tools:use`,
`tools:manage_runtime`, `inbox:manage`, `tasks:assign`, `tasks:assign_scope`, `tasks:manage_active_checkouts`) in `services/agents.js` `create()` and
`activatePendingApproval()`, and again for join-request agents via `services/invite-grants.js`. With 0002 an agent holding `agents:configure` can rewrite other agents' sandbox keys.
Both 1005 and 1012 additionally grant `tasks:assign` in `routes/agents.js` (`applyDefaultAgentTaskAssignGrant`, hire + create routes) and in the company import
(`services/company-portability.js`).

*Fix.* **0005e (1012 only):** `NEW_STANDARD_AGENT_DEFAULT_GRANT_KEYS = []` in `services/agent-permissions.js`; all consumers map over it, so create, approval
activation and invite join add nothing (an invite's own `defaultsPayload.agent.grants`, set by the board, still apply). **0005c / 0005d (1005 + 1012):**
`applyDefaultAgentTaskAssignGrant` and the import path keep creating the (inactive) membership but no longer grant `tasks:assign`.
*Guard.* With the list empty, `tx.insert(principalPermissionGrants).values([])` throws in drizzle ("values() must be called with at least one value"), which would 500 every create/hire/join approval; the 1012 variant of 0005a guards both inserts (`create()` and `activatePendingApproval()`) with `NEW_STANDARD_AGENT_DEFAULT_GRANT_KEYS.length > 0`. (1005 has no such inserts.)
Grants that remain for a new agent: none. Agents need none to work: checkout, comment and status changes on issues assigned to them, reading, and the
heartbeat protocol authorize on assignment/run ownership, not on grants. `canCreateAgents=false` and the sandbox defaults are unchanged. The board adds any grant
explicitly (agent edit / role-and-grants). Unchanged on purpose: built-in agents (`built-in-agents.js` grants its own set), the CEO-role `tasks:assign` handling, and
manifest-listed grants in a company import (board-reviewed).

*Upgrade 1005 to 1012 does not add these grants to existing agents:* the source comment says existing agents are not backfilled (`agent-permissions.js:2`); the startup
`backfillPrincipalAccessCompatibility` (`server index.js:~510`, `services/principal-access-compatibility.js:41-93`, byte-identical to 1005) only inserts agent memberships
and human-role grants; migrations 0294..0305 contain no `principal_permission_grants` writes.

## 6. Git worktree common dir (0006a, 0006b)

Patches: `0006a-git-common-dir-spawn.patch` (server `services/heartbeat.js`), `0006b-git-common-dir-sandbox-check.patch`
(adapter-utils `local-process-sandbox.js`). One logical change, split only because `apply.sh` handles one target file per patch.

**Problem.** Worktrees live in `<repo>/.paperclip/worktrees/<name>`; their `.git` is a file pointing into the repo's common git dir, which the
`filesystemScope=workspace` sandbox does not mount, so every git command fails ("not a git repository"). `filesystemExtraPaths` ro only allows
read-only git; rw is rejected by the sandbox ("no outbound restore mapping"), and a per-agent static path cannot name per-project repos.

**Fix.** 0006a, at spawn for local `claude_local` runs (after the 0003/0005b hooks): if `<workspace>/.git` is a file, resolve gitdir + commondir
(realpath), require the common dir inside the allowed workspace roots (0003's check), and add for that run only: common dir rw, plus ro
overlays on `hooks`, `config`, `info` and `worktrees/*/config.worktree` (`hooks`/`info` are created if missing). Failures skip the mount (run continues
without git). Warn log `event=sandbox_git_common_dir`. Nothing is stored on the agent. 0006b exempts only paths registered by 0006a (process-global
set) from the outbound-restore check.

**Trade-off.** The agent gets rw on its own project's common `.git`: it can rewrite refs/history/objects, delete branches, `git gc`, affect the main
checkout and other worktrees of that project. Host-side execution vectors (hooks, core.fsmonitor/sshCommand/aliases/includes via config) are blocked by
the ro overlays. Other projects' repos stay invisible.

**Known limits.** `git config` writes and `--set-upstream` fail (config is ro; `git branch -d` works with a harmless warning). Push is not covered
(needs the network allowlist + token, separate topic). Not tested with a real Paperclip run at patch time.

## 7. Pipeline structure is board-only (0007)

Patch: `0007-pipeline-structure-board-only.patch` (server `routes/pipelines.js`; `routes/pipelines.js` is identical in 1005 and 1012, one file for both).

**Problem.** `pipelines:write` (granted to agents for case work) also authorizes rewriting the pipeline itself: `PATCH /pipelines/:id` (incl. `enforceTransitions`,
archive), stage create/update/delete (incl. `requireApproval`/approver config), `PATCH .../stages/:id/automation-env`, `PUT .../transitions`, pipeline
guidance documents (`PUT/restore .../documents/:key`), and `POST /companies/:id/pipelines`. An agent could remove the approval gates it works under.

**Fix.** `denyAgentPipelineStructureMutation(req, operation)` is the first statement of those nine handlers: `req.actor.type === "agent"` (agent key or run JWT)
gets 403 `pipeline_structure_board_only` and a warn log `event=pipeline_structure_denied` (operation, agentId, runId, method, path). Board actors are untouched.
Case routes (ingest, batch, breakdown, case documents, transitions of cases, claim/release) are not guarded. There is no pipeline DELETE route in these versions.
Side effect: anything that drives pipeline setup with an agent token (e.g. a setup script) must use a board key.
*Addendum.* `POST /cases/:id/transition` with `force:true` skips the transition graph / gates (`services/pipelines.js:~2559`). Agent actors now get 403
`pipeline_structure_board_only` (operation `force_transition`, warn log `pipeline_structure_denied`), mirroring the force-release check. Board unchanged.

## 8. Redacted placeholders in adapterConfig updates (0008)

Patch: `0008-adapterconfig-redacted-restore.patch` (server `services/agents.js`; byte-identical hunks for 1005 and 1012, applies after 0005a).

**Problem / root cause.** `GET /agents/:id` returns a redacted copy of adapterConfig; some values (e.g. `networkAllowlist` hosts) come back as the literal
`"***REDACTED***"`. The UI's secret "Agent access" binding flow builds its save from the GET-derived adapterConfig and PATCHes it back. The server restores redacted
values only inside `env` (`restoreRedactedAgentEnv`, `routes/agents.js` ~2552/4507 in 1005), so for every other key the literal was stored: 11 agents ended up with
`networkAllowlist: ["***REDACTED***"]` instead of `api.anthropic.com` (sandbox then blocks the model API).

**Fix.** Choke points in `services/agents.js`: `update()` (every route that changes adapterConfig calls it), `create()` and `activatePendingApproval()` (hire activation).
For every adapterConfig key other than `env`: an incoming value containing the literal is accepted only as an **unchanged echo**, i.e. deep-equal to what GET shows for the
stored value (`redactAgentAdapterConfig({key: stored})`); it is then replaced by the stored value (warn `redacted_value_restored`). Anything else (host removed or added next to a
placeholder, no stored value, stored value itself redacted, any create) fails 422 `redacted_value_in_update` (warn `redacted_value_rejected`). Values without the literal are
stored as sent (board edits with clean values work). One patch file serves 1005 and 1012 (applies after 0005a).

**Limits.** Agents already holding the literal are not repaired; any update echoing it is rejected until the board sends clean values for that key. Note 1012's
redaction showed no placeholder for `api.anthropic.com` in a harness run, so the failure may depend on the redaction rules of the running version.

## 9. Agent permissions grants are board-only (0009)

Patch: `0009-agent-permissions-grant-board-only.patch` (server `routes/agents.js`, same hunk for 1005 and 1012).

**Problem.** `PATCH /agents/:id/permissions` lets a CEO-role agent change permissions of any agent in the company, itself included; setting `canCreateAgents=true`
(which also turns on `tasks:assign` via `effectiveCanAssignTasks`) gives agent-creation and task-assignment power without a board decision.

**Fix.** For agent actors, a body with `canCreateAgents: true` or `canAssignTasks: true` gets 403 `permissions_grant_board_only` (warn `agent_permissions_grant_denied`).
Chosen: both grants are board-only; the CEO may still send `false` for them (revoking) and change the other permission fields. The CEO role is checked first as before.
The CEO does not need to grant `tasks:assign` (0005c: the board grants it explicitly). Board actors are untouched.

## 10. Startup CEO sync grants agents:configure + skills:create (0010)

Patch: `0010-no-ceo-default-change-grants.patch` (server `services/built-in-agents.js`; identical file in 1005 and 1012). Cleanup of existing rows: `cleanup-agent-grants.js` (not run by apply.sh).

**Problem.** `ROOT_AGENT_DEFAULT_CHANGE_GRANTS = ["agents:configure","skills:create"]` (`built-in-agents.js:307`, both versions) is applied by `ensureRootAgentDefaultChangeGrants`
(`:~614-628`, only when the company has exactly one non-built-in, parentless, non-pending `ceo`-role agent) through `ensureCompanyDefaultAgentGrants` (`:630`) which runs
(a) at every server start: `index.js:827` `reconcileBuiltInAgentsOnStartup` -> `built-in-agents.js:1740`, and (b) after every agent create: `routes/agents.js:4000` (1005) / `:4140` (1012).
Each run calls `setPrincipalPermission(..., true)` (upsert, hence the re-touched timestamps). A CEO agent therefore always holds the change grant that 0002 used as its gate.

**Fix.** The constant is `[]`; `ensureAgentDefaultGrants` returns 0 for an empty list, the rest of the sync (membership, built-in agent grants such as reflection-coach `*:suggest-changes`) is unchanged.
Existing rows stay until removed: run `node cleanup-agent-grants.js` (SELECT/dry run, per company/agent counts) then `--apply` (one transaction, deletes every `principal_type='agent'` row
for those two keys). Note: it removes explicit grants for all agents, including any the board gave on purpose; re-grant afterwards if needed. Restart after apply.sh.

## 11. Board can grant/revoke pipelines:write via PATCH /agents/:id/permissions (0011)

Patches: `0011a-agent-permissions-can-write-pipelines-schema.patch` (shared `dist/validators/agent.js`) and `0011b-agent-permissions-can-write-pipelines.patch` (server `routes/agents.js`); same hunks for 1005 and 1012, 0011b applies after 0009.

**Problem.** `pipelines:write` is checked by `routes/pipelines.js`, but no REST path let the board grant it to an agent (`PATCH /agents/:id/permissions` only knew canCreateAgents/canCreateSkills/canAssignTasks).

**Fix.** `updateAgentPermissionsSchema` gets `canWritePipelines: z.boolean().optional()` (the existing required fields canCreateAgents and canAssignTasks must still be sent). Handler: after the `tasks:assign` grant, a boolean
`canWritePipelines` calls `access.setPrincipalPermission(company, "agent", id, "pipelines:write", value, userId)` (same helper as tasks:assign): true upserts an unscoped row (scope null), false deletes the agent's pipelines:write row(s);
omitted leaves it unchanged. Agent actors (even CEO) get 403 `permissions_grant_board_only` for any value, true or false (warn `agent_permissions_grant_denied`). Not added to the response shape or activity details.
Note: the shared package is now a patch target (validator lives there), so `paperclipai update` must be followed by apply.sh as usual.

## 12. NO_PROXY=localhost in allowlist runs (0012)

Patch: `0012-sandbox-no-proxy-localhost.patch` (adapter-utils `dist/local-process-sandbox.js`; one patch for 1005 and 1012, applies after 0001/0004/0006b).

**Problem.** In a `networkScope=allowlist` run the sandbox sets `HTTP(S)_PROXY` to its egress proxy (`http://127.0.0.1:31337`) and, just before, resets `NO_PROXY`/`no_proxy` to `""`. The run has its own network namespace (`--unshare-net`),
so an app the agent starts inside the run on localhost is private, but curl/Playwright/etc. send that localhost traffic to the proxy, which answers 403 (proven: 403 via proxy, 200 with `NO_PROXY=localhost`).

**Fix.** In the allowlist branch, after the proxy vars, `NO_PROXY` and `no_proxy` get `localhost` (appended with a comma to any existing non-empty value). `127.0.0.1` and `::1` are deliberately NOT added:
allowlisted HOST services are reached through the proxy on 127.0.0.1 (vault :8790, memory :8765) and must keep going through it.
**Convention:** in-sandbox apps are addressed as `http://localhost:<port>` (bind 127.0.0.1 or localhost); host services stay on `127.0.0.1:<port>` via the proxy. Non-allowlist scopes unchanged (no proxy set, `NO_PROXY=""`).

## 13. Agents need an explicit tasks:assign grant to assign work to another agent or a board user (0013a, 0013b)

Patches: `0013a-agent-assign-needs-explicit-grant.patch` (server `services/authorization.js`) and `0013b-agent-access-no-simple-default.patch` (server `routes/agents.js`); one hunk each, byte-identical for 1005 and 1012 (line offsets differ only), apply after 0011b/0012.

**Problem.** After 0005c/d/e a new agent holds no `tasks:assign` row, but the check is still default-open. (1) *Enforcement:* `authorization.js` agent branch of `decideBase` (1012 `:1653-1685`, 1005 `:1617-1650`) allows `tasks:assign`
for any non-terminated, non-pending agent ("simple mode"; hard-coded, there is no company/instance setting for it) via `decideVisibleIssueWrite()` (`allow_visible_issue_write`) or, for non-standard trust, `allow_simple_company_member`; a grant is consulted only when the
target agent/project/issue carries a restrictive `authorizationPolicy` (`assignmentPolicy.mode=protected` or `agentVisibility.mode=private`, `evaluateAuthorizationPolicyForAssignment` `:84-155`). Callers: `routes/issues.js` `assertCanAssignTasks` (`:3138`) on issue create (`:8249`, **always for agent actors**), child create (`:8494`), suggested tasks (`:3745`),
split children (`:8660`), PATCH assignee change except workflow-controlled hand-offs / returning to creator (`:9426`), checkout of an issue assigned to someone else (`:10729`); also status cards, skill-test harness, tool-access test, plugin host, native runner tool authority.
(2) *Display:* `routes/agents.js` `buildAgentAccessState` (1012 `:1258-1301`, 1005 `:1249-1292`) reports `canAssignTasks=true, taskAssignSource="simple_default"` for any agent with an active membership (the only reader of `access.canAssignTasks`; GET `/agents/:id`).
So a non-manager agent really could create issues assigned to other agents, and PATCH the assignee of issues it can write.

**Fix.** 0013a: in that agent branch, after the restricted-policy handling and before the default-open rule, if the resource has `assigneeUserId`, or `assigneeAgentId` that is not the actor, `decideWithTaskAssignmentGrants("agent", actorAgentId)` must allow
(explicit `tasks:assign` row, or `tasks:assign_scope` covering the scope); otherwise its `deny_missing_grant` / `deny_scope` decision is returned (HTTP 403). Chosen narrow: self-assignment and unassigned issues stay default-open, because agents always pass through `assertCanAssignTasks` on every issue create and
on checkout; a blanket requirement would block agents from creating any issue. 0013b: removes the `simple_default` branch (result `none`/false unless CEO role, `canCreateAgents`, or an explicit row), so the API matches enforcement. CEO-role in the display is `ceo_role` (display only);
enforcement of the CEO is by its explicit row like everyone else. Board actors and the human simple-mode default (`:1253`) are untouched. Board grants stay possible (agent edit / role-and-grants / `PATCH /agents/:id/permissions canAssignTasks`, board-only by 0009).
Harness (scratch, not shipped): fake-db run of `authorizationService.decide` before/after: engineer/qa to another agent or a user: allow -> deny; self, unassigned: allow; CEO and Architect (explicit rows) to another agent: allow.

## 14. Interaction wake for the addressee (0014)

Patch: `0014-interaction-pending-addressee-wake.patch` (server `modules/run-dispatch/adapters/postgres.js`).

**Problem.** A wake with reason `interaction_pending` was not accepted as an interaction wake, so an agent addressed by a pending interaction (a question or confirmation request on an issue)
was not woken for it.

**Fix.** The wake counts as an interaction wake only while the interaction it names still exists on this issue, in this company, with status `pending`, re-read under the issue lock (any lookup error means "no").

## 15. Public-web wildcard in the allowlist proxy (0015)

Patch: `0015-sandbox-public-web-wildcard.patch` (adapter-utils `local-process-sandbox.js`).

**Problem.** Agents that must read the open web needed the host network (no box), because the allowlist accepts exact hostnames only.

**Fix.** A `*:<port>` entry allows any host on that port whose every resolved address is public (loopback, private, link-local, CGNAT/tailnet, multicast, unique-local, and IPv4 embedded in IPv6 forms are refused). The proxy resolves once and connects to the checked address, so a second lookup cannot rebind to an internal one.
A bare `*` and `*.domain` stay rejected.

## 16. Own Claude config folder per agent (0016)

Patch: `0016-per-agent-claude-config.patch` (adapter-claude-local `server/execute.js`).

**Problem.** Every sandboxed Claude agent of every company mounted the same read-write Claude config folder: shared conversations, settings and hooks.

**Fix.** A boxed agent gets its own folder under its runtime state dir (mode 0700), seeded once with only the theme from the shared `settings.json`; credentials and conversations are never copied. Authentication stays with `CLAUDE_CODE_OAUTH_TOKEN`. Managed AI connections keep the old behaviour.

## 17. Shared box helper (0017)

Patch: `0017-boxed-sandbox-helper.patch` (adapter-utils `local-process-sandbox.js`).

**Problem.** Paperclip's sandbox is wired by hand into the Claude and Codex adapters. Each adapter builds its own mount list and trusted URLs, mounts whatever `filesystemExtraPaths` says (including the home directory, the database or another agent's folder), and nothing records which adapter types are really boxed. A denied connection leaves no trace.

**Fix.** One entry point, `boxedSandboxOptions(...)`, that an adapter passes as `localProcessSandbox` to its spawn call; `ensureBoxedRuntimeDir(dir)` makes the agent's runtime folder (0700); `registerBoxedAdapter(type)` announces the type.

* *Trusted URLs.* The proxy's extra trusted URLs (`networkTrustedUrls`) come only from the `trustedUrls` input, which the adapter fills with the Paperclip API URL and runtime-tools endpoints it computed itself. They are never read from `env.PAPERCLIP_API_URL`, which `config.env` can override. An entry that is not an http(s) URL makes the call throw.
* *Home and instance guard.* Every mounted path (workspace, runtime dir, managed and extra paths) is resolved through symlinks first and refused when it contains the home directory, or lies inside the home or the instance directory (`$PAPERCLIP_HOME/instances/<id>`) unless it is below the instance's `workspaces` or `projects`, below this agent's own `companies/<companyId>/agents/<agentId>` directory, or below a workspace root. A workspace root that holds the home or the whole instance is ignored. The adapter passes `agentId` and `companyId`; without them nothing under `companies/` can be mounted.
* *Frozen registry.* The boxed-adapter registry is a `{has, add}` object defined once on `globalThis[Symbol.for("paperclip.hardening.boxedAdapters")]` (not writable, not configurable); `add` takes only the known type names. The admission (0005f) asks `registry.has(type)`.
* *Denied connections.* One structured log line per refused proxy target: `event=sandbox_network_denied`, `agentId`, `runId`, `host`, `port` (no path or query; the host is sanitised because the agent chooses it), at most 20 per run, then one line with `rateLimited:true`.
* *Operator-visible change.* An extra read-only path inside the home or the instance is refused for boxed types; paths such as `/opt/...` are unaffected.

## 18. Environment scrub (0025)

Patch: `0025-sandbox-env-scrub.patch` (adapter-utils `server-utils.js`).

**Problem.** Adapters build the child environment as `{ ...process.env, ...agentEnv }`, so a boxed child inherits the server's database URL, API keys and `NODE_OPTIONS`; the sandbox builder cannot tell them from the agent's own credentials.

**Fix.** A confined child gets BASE (`PATH`, `HOME`, `LANG`, `LC_*`, `TZ`, `TERM`, proxy names) plus the names the adapter lists in `localProcessSandbox.envPassNames` (the keys of the adapter's own env object; `boxedSandboxOptions` fills it). A missing or malformed list passes BASE only. `HOME` is always set by the scrub itself (the box home, else the server's). A listed `PAPERCLIP_*` name passes only when its value differs from the server's own (`PAPERCLIP_API_URL` excepted) and never when it looks like a secret or key. `NODE_OPTIONS`, `NODE_PATH`, `LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `GLIBC_TUNABLES` and `PYTHON*` are never passed. The patch announces itself on `Symbol.for("paperclip.hardening.envScrub")` (value `true`, not writable); the admission refuses a boxed type without it. The names are read when the child starts, so an adapter that adds variables after building the box re-sets the list right before the spawn.

## 19. OpenCode in the box (0019, 0019b, 0019c, 0019d)

Patches: `0019-opencode-boxed-run.patch` (`execute.js`), `0019b-opencode-boxed-model-discovery.patch` (`models.js`), `0019c-opencode-boxed-runtime-config.patch` (`runtime-config.js`), `0019d-opencode-boxed-environment-test.patch` (`test.js`), all in adapter-opencode-local.

**Problem.** `opencode_local` has no sandbox settings. It runs as the server user, with the server's environment, reads `~/.config/opencode` and writes its state into the server user's home.

**Fix.** With `filesystemScope` or `networkScope` on the agent, the run goes through 0017 and 0025. The agent's home is `<instance>/companies/<company>/agents/<agent>/opencode-runtime/home` (config, data, cache, state; two agents never share one). A fixed box environment disables the model-list download, auto-update, language-server download and project config. Skills are copied into the box home, not linked, because the box never mounts the skills catalog. A managed AI connection's credential home is used as the box home instead. 0019b runs `opencode models` in the box; 0019c takes `{env:NAME}` placeholders, the provider config and the small model only from the agent's own env (a placeholder with no value is refused up front) and keeps the config copy in the runtime dir; 0019d runs the "Test environment" probes in a throw-away box and skips them, with an error check, when the box cannot be set up. A local probe starts the server's own OpenCode (`PAPERCLIP_OPENCODE_COMMAND`, else `opencode` on the server's PATH), never `command` from the request: that field is just what a Test request says it is. The managed AI connection's credential home is accepted as the box home only when it is a direct child of the temp dir named `paperclip-ai-<company>-...`.

**Defaults and credentials.** A new agent's allowlist is the four common provider hosts (0005a, `baseAllowlists.opencode_local` overrides). API keys reach the CLI only from the agent's own secrets: `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`.

## 20. Claude in the box (0026, 0026b, 0026c)

Patches: `0026-claude-boxed-adapter.patch` (`execute.js`), `0026b-claude-test-probe-project-settings.patch` (`test.js`), `0026c-claude-acp-probe-project-settings.patch` (`acp.js`), all in adapter-claude-local.

**Problem.** Stock `claude_local` builds its own sandbox object, passes the server's environment to the box, trusts `env.PAPERCLIP_API_URL` after `config.env` is merged, and its "Test environment" probe runs `claude --print` in the agent's workspace: the hooks of a `.claude/settings.json` written by the agent would run as the service user, outside the box.

**Fix.** 0026 moves the adapter onto 0017 and 0025: the box gets the agent and company id, the trusted URLs the adapter computed itself, the managed prompt cache read-only, and the child sees BASE plus the keys of the adapter's own env (re-set right before each spawn, because workspace variables are added after the box is built). The version probe and `claude login` run in the same box. 0026b and 0026c make every probe of a local target use `--setting-sources user` in an empty temporary folder, whatever the request's config says (a request without a sandbox scope is just as able to carry a workspace with hooks), and drop the request's `CLAUDE_CONFIG_DIR` unless it is the credential home the server made for a managed AI connection of the company (`<tmp>/paperclip-ai-<company>-<grant>-*/provider`); the probe then uses the server's own Claude folder. A side effect for operators: the probe ignores the project's Claude settings and the agent's own Claude folder, so it can differ from a real run.

## 21. More spawn-time enforcement (0003b)

Patch: `0003b-hermes-engine-env-redirects.patch` (server `services/heartbeat.js`, extends 0003).

**Problem.** 0003 restores the stored sandbox keys and drops launch-changing environment, but a run-level value could still move a CLI's home or config (`HOME`, `XDG_*`, `OPENCODE_*`, `GEMINI_CLI_HOME`, ...), switch a boxed agent to the ACP engine, point the box's trusted URL at another host (`PAPERCLIP_API_URL`), or change what a Hermes agent's wrapper does. A boxed Hermes agent had no spawn-time enforcement at all.

**Fix.** A run-level value (issue assignee, project, routine, environment, run adapterConfig) for these names is compared with the stored plain value: equal is kept; a stored value comes back; otherwise the variable is removed. Each action is logged (`event=sandbox_enforcement action=drop_env|restore_env`). Covered: the state redirects of every profile (`stateEnv` of the plugin's `BOX_PROFILES`; a drift test compares the lists), `HOME`/`XDG_*`, `PAPERCLIP_*_PROVIDERS`, `PAPERCLIP_API_URL`, `PAPERCLIP_RUNTIME_TOOLS_*`, all `HERMES_SANDBOX_*` and `HERMES_HOME`, and the key `engine`. The server's own per-run credential home of a managed AI connection is exempt for exactly the names the server's `managedAiHomeEnvironment()` sets (`HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `CODEX_HOME`, `GROK_HOME`, `CLAUDE_CONFIG_DIR`); any other state or provider-routing name stays dropped in a managed run too. A boxed Hermes agent (stored `command` equals the wrapper) gets the same cwd check as the scoped types, `command` and `hermesCommand` are restored, and the wrapper path is read once at startup. The workspace roots the server enforces are published for 0017 (`Symbol.for("paperclip.hardening.workspaceRoots")`, frozen); a second copy of the module that publishes a different value makes the server refuse to start.

## 22. Table-driven admission (0005f)

Patch: `0005f-table-driven-admission.patch` (server `services/heartbeat.js`, replaces the rule body of 0005b).

**Problem.** 0005b admitted `claude_local` with a `filesystemScope` and `hermes_local` with the wrapper, and refused everything else. Adding a boxed adapter meant editing the rule, and it did not check that the adapter was really set up for the box.

**Fix.** A table (`SANDBOX_ADMISSION_0005F`, equal to the plugin's `BOX_PROFILES`) lists the scoped types. A scoped agent needs all of: `filesystemScope: "workspace"`, a `networkScope` of `deny` or `allowlist`, `engine: "cli"` for types with an ACP engine, the adapter registered through 0017 in this process, and the environment scrub of 0025 loaded. In v0.2.0 only `claude_local` and `opencode_local` register, so `codex_local`, `gemini_local`, `cursor`, `pi_local`, `kimi_local` and `grok_local` are refused ("the adapter is not registered as boxed in this server"); their patches are planned for later versions and need no change to the rule. `hermes_local` needs `command` and, when set, `hermesCommand` to be the wrapper. `cursor_cloud`, `openclaw_gateway`, `hermes_gateway`, `http` and `process` run only when `remoteExceptions` of the hardening settings file lists the agent id and type; the file is read again, with the checks of 0003, at each such run (an untrusted file means no exceptions), and every admitted run logs `event=sandbox_remote_exception_used`. Any other type is always refused. The refusal names every missing piece (`Sandbox policy: run refused, ...`).

## 23. The "Test environment" route is for board users (0027)

Patch: `0027-adapter-test-board-only.patch` (server `routes/agents.js`).

**Problem.** `POST /companies/:companyId/adapters/:type/test-environment` starts the adapter's probes (a CLI hello turn, model discovery) on the server as the service user, outside any agent box, from the `adapterConfig` in the request. The route only asked for the right to create agents (`assertCanCreateAgentsForCompany`), which every CEO-role agent has, so an agent could ask for a probe of a config of its choosing (a workspace it wrote, a `CLAUDE_CONFIG_DIR` it wrote, an OpenCode `command`).

**Fix.** The first statement of the handler refuses every actor that is not a board user (403, code `adapter_test_board_only`, logged as `event=adapter_test_environment_denied`). The probes were also hardened by 0026b, 0026c and 0019d so that a board user's request cannot be steered by files an agent wrote. Agent flows that call the route themselves (none are known) would be refused.
