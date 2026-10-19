#!/usr/bin/env node
// One-time cleanup (NOT run automatically): remove the explicit agents:configure / skills:create grants that agent principals got
// from the pre-0010 startup CEO sync (and from the upstream new-agent defaults before 0005e).
//   node cleanup-agent-grants.js           SELECT only: print counts per company/agent
//   node cleanup-agent-grants.js --apply   DELETE them, in one transaction (rolled back on error)
// DB: embedded Postgres 127.0.0.1:54329, user/db paperclip, password 'paperclip' (override with PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE).
// `pg` is loaded from the live install tree (PAPERCLIP_TREE or ~/.paperclip/cli/current). Prints ids/counts only, no secrets.
const { createRequire } = require("node:module");
const fs = require("node:fs"), path = require("node:path"), os = require("node:os");
const tree = fs.realpathSync(process.env.PAPERCLIP_TREE || path.join(os.homedir(), ".paperclip/cli/current"));
const req = createRequire(path.join(tree, "node_modules", "x.js"));
let Client;
try { ({ Client } = req("pg")); } catch (e) {
  try { ({ Client } = createRequire(req.resolve("@paperclipai/db"))("pg")); } catch { console.error("cannot load 'pg' from " + tree); process.exit(1); }
}
const KEYS = ["agents:configure", "skills:create"];
const apply = process.argv.includes("--apply");
(async () => {
  const c = new Client({ host: process.env.PGHOST || "127.0.0.1", port: Number(process.env.PGPORT || 54329),
    user: process.env.PGUSER || "paperclip", password: process.env.PGPASSWORD || "paperclip", database: process.env.PGDATABASE || "paperclip" });
  await c.connect();
  try {
    await c.query("BEGIN");
    const where = "principal_type = 'agent' AND permission_key = ANY($1)";
    const rows = (await c.query(
      `SELECT g.company_id, g.principal_id AS agent_id, a.name, g.permission_key
         FROM principal_permission_grants g LEFT JOIN agents a ON a.id::text = g.principal_id::text
        WHERE g.${where} ORDER BY g.company_id, a.name, g.permission_key`, [KEYS])).rows;
    const per = {};
    for (const r of rows) {
      const k = `${r.company_id} ${r.agent_id} ${r.name ?? "(deleted agent)"}`;
      (per[k] ??= []).push(r.permission_key);
    }
    for (const [k, v] of Object.entries(per)) console.log(`${k}: ${v.join(", ")}`);
    console.log(`${rows.length} grant row(s) on ${Object.keys(per).length} agent(s)`);
    if (!apply) { await c.query("ROLLBACK"); console.log("dry run (SELECT only); pass --apply to delete"); return; }
    const del = await c.query(`DELETE FROM principal_permission_grants WHERE ${where}`, [KEYS]);
    await c.query("COMMIT");
    console.log(`deleted ${del.rowCount} row(s)`);
  } catch (e) {
    await c.query("ROLLBACK").catch(() => {});
    console.error("failed, rolled back:", e.message); process.exitCode = 1;
  } finally { await c.end(); }
})();
