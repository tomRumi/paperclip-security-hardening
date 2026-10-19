# Verifying the hardening after install or update

Run as the agent user unless noted.

1. `host/patches/apply.sh --check` prints `already applied` for every patch (rc 0). `0005e` is skipped on 2026.1005.0 (not needed).
2. Start any agent run; the Paperclip log contains `sandbox_enforcement` lines for it (spawn-time enforcement active).
3. Negative tests with an agent API key (never the board key):
   * `PATCH /api/agents/<own id>` with `{"adapterConfig":{"filesystemScope":null,"networkScope":null}}` returns 403.
   * A request from inside the sandbox to a host not on the allowlist fails.
   * An agent whose adapter has no sandbox (or `hermes_local` without the wrapper) is refused at spawn.
   * A file written outside the workspace by an agent does not appear on the host.
4. Admin: `sudo -l -U <agent user>` reports that the user may not run sudo; `itsec-make-manifest --tree ...` succeeds only if every marker is present.
5. The plugin's "Hardening" page shows the patch status and all agents compliant.
