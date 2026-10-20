# Verifying the hardening after install or update

Run as the agent user unless noted. The plugin's self-test (Hardening page, "Run self-test") already tests the admission rule and the box, environment and network behaviour (items 6, 7, 10 and 11) with a real bubblewrap sandbox and no credentials; the steps here check them by hand on live agents.

1. `host/patches/apply.sh --check` prints `already applied` for every patch (rc 0). `0005e` is skipped on 2026.1005.0 (not needed).
2. Start any agent run; the Paperclip log contains `sandbox_enforcement` lines for it (spawn-time enforcement active).
3. Negative tests with an agent API key (never the board key):
   * `PATCH /api/agents/<own id>` with `{"adapterConfig":{"filesystemScope":null,"networkScope":null}}` returns 403.
   * A request from inside the sandbox to a host not on the allowlist fails.
   * A file written outside the workspace by an agent does not appear on the host.
4. Admin: `sudo -l -U <agent user>` reports that the user may not run sudo; `itsec-make-manifest --tree ...` succeeds only if every marker is present.
5. The plugin's "Hardening" page shows the patch status and all agents compliant.

## Admission (which agents run)

6. Give an agent each of these types and start a run; the result is in the run's error and in the log (`event=sandbox_enforcement action=refuse_unsandboxed`, or `sandbox_remote_exception_used`):
   * `claude_local` and `opencode_local` with `filesystemScope: "workspace"`, a `networkScope` and (Claude) `engine: "cli"`: the run starts.
   * The same agent with `filesystemScope` removed, `engine: "acp"` (Claude), or `networkScope` removed: refused, and the message names the missing piece.
   * `hermes_local` without the wrapper as `command`: refused. With a `hermesCommand` that is not the wrapper: refused.
   * `codex_local`, `gemini_local`, `cursor`, `pi_local`, `kimi_local`, `grok_local`: refused ("not registered as boxed in this server"), even with the box settings. This is expected in v0.2.x.
   * `http`, `process`, `cursor_cloud`, `openclaw_gateway`, `hermes_gateway`: refused until the agent is listed under Remote exceptions; after the line is saved the next run starts (no restart) and the log shows `sandbox_remote_exception_used`. Removing the line refuses it again. Any other type stays refused with an exception too.

## Cleared environment and credentials

7. In a run of a boxed Claude or OpenCode agent, have the agent print the names (not the values) of its environment variables, for example `env | cut -d= -f1 | sort`. It lists `PATH`, `HOME`, `LANG`, the `PAPERCLIP_*` run variables, the proxy variables and the secrets bound to that agent, and none of the server's: no `DATABASE_URL`, no `NODE_OPTIONS`, no key you set only in the server's own environment. `HOME` is inside the agent's runtime folder.
8. With a key set only in the server's environment (for example `ANTHROPIC_API_KEY`) and no secret bound to the agent, the agent's run fails to authenticate. After you bind the secret to the agent under the exact variable name (`CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, ...), it works.
9. A run-level override is dropped: set `HOME`, `XDG_CONFIG_HOME` or `PAPERCLIP_API_URL` on a project, routine or issue for a boxed agent and start a run; the log has `event=sandbox_enforcement action=drop_env` (or `restore_env`) for each, and the agent sees its own values.

## Network and folders

10. From inside a boxed Claude or OpenCode run, a connection to a host that is not on the agent's allowlist fails, and the log has exactly one `event=sandbox_network_denied` line for it with the agent id, run id, host and port (at most 20 per run). A host that is on the list works and logs nothing.
11. Inside the box the agent cannot read or write outside its workspace and its runtime folder: not the home directory (`~/.ssh`, `~/.paperclip`), not another agent's or company's folder under the instance, and not the instance's database or secrets.
12. Two agents of the same type have different `HOME` folders (`<instance>/companies/<company>/agents/<agent>/<type>-runtime/home`) and do not see each other's sessions.

## Test environment probes

13. On a boxed Claude agent whose workspace holds a `.claude/settings.json` with a hook that writes a file, press "Test environment": the hook does not run (the probe loads user settings only and starts in an empty folder). The same when the request leaves out the sandbox settings, and when `CLAUDE_CONFIG_DIR` in the agent's environment points at a folder whose `settings.json` holds such a hook. On a boxed OpenCode agent the probes run inside the box: a probe that tries to read outside the workspace fails, and a `command` in the request is not started (the server's own `opencode` is).
13a. With an agent's API key (not a board user's session), `POST /api/companies/<company>/adapters/claude_local/test-environment` answers 403 `adapter_test_board_only` and the log has `event=adapter_test_environment_denied`. The same call from a board user is processed.
13b. With "Box OpenCode agents" switched off (and the rest on), a boxed `opencode_local` agent's run is refused with "the opencode_local adapter is not registered as boxed in this server", and a boxed Claude agent still runs.
13c. After a Paperclip update that replaced the files and makes one patch not fit (the plugin's log: "no longer fit this Paperclip; skipped"), every other protection is applied (restart as usual), the unfit one stays switched on and its row shows "update needs admin decision", and one HIGH alert exists. With "Box Claude agents" unfit, "Only boxed agents run" is still applied and a Claude agent is refused ("not registered as boxed"). If the unfit protection is in the files right now (a plugin update whose patches do not fit the built tree), nothing is rebuilt and Save asks for the confirmation. If Paperclip now contains the change itself, the row says "Now part of Paperclip ... no longer needed" and there is no alert.
13d. In `local_trusted` mode the Hardening page shows the local_trusted line and one HIGH alert exists.

## New agents

14. Create an agent of each boxed type with a hostile body: `engine: "acp"`, an `env` with `HOME`, `NODE_OPTIONS`, `CODEX_HOME` and a secret reference under a normal name. The stored agent has `engine: "cli"` (where the type has an ACP engine), the box settings and no `canCreateAgents`; the redirect names are gone, the credential stays, and the log has `event=new_agent_defaults` with `droppedEnv` (names only).
