// birdshot END-TO-END test (companion to test/sql/birdshot.test).
//
// WHY THIS EXISTS
// ---------------
// `make test` runs test/sql/birdshot.test IN-PROCESS: it calls
// `birdshot_authorize(sid, query)` directly and checks the boolean it returns.
// That proves the decision logic. It does NOT prove that a *false* decision
// actually blocks a real quack client on the wire — the only thing that matters
// in production. This harness closes that gap: it stands up a real quack SERVER
// with birdshot wired in as `quack_authentication_function` /
// `quack_authorization_function` (exactly as packages/db/src/birdshot.ts does),
// connects real quack CLIENTS, and replays every authorize assertion from the
// .test end-to-end — asserting the client is allowed/blocked AND that the
// verdict was attributed to birdshot via its own audit log.
//
// TWO CLIENT PATHS (both real, both exercised)
//   Form B  quack_query(uri, '<verbatim SQL>')  -> the whole statement runs
//           server-side; birdshot sees the EXACT query string. Covers the full
//           authorize matrix incl. joins, subquery-smuggle, CTEs, forbidden
//           statements, file readers, casts. This is how the .test lines are
//           replayed.
//   Form A  ATTACH 'quack:...'; SELECT cols FROM lake.t  -> quack push-down; the
//           server sees the positional `#N` form. Authentic agent path; used for
//           the column-projection cases. NOTE (product limitation): on this path
//           quack cannot carry a JOIN or ANY cross-table/correlated subquery —
//           it throws "Multiple streaming scans" BEFORE birdshot runs. So the
//           realistic scan path is single-table-flat only; everything richer must
//           go through Form B (quack_query). Surfaced here because it is easy to
//           assume ATTACH+scan covers what it does not.
//
// VERDICT (avoids false greens):
//   allow  := birdshot logged `allow` for this exact query AND the client got
//             rows back without throwing.
//   deny   := birdshot logged `deny` for this exact query AND the client was
//             blocked (threw / no rows). Both halves required: the audit log
//             attributes the block to birdshot (not to an unrelated quack error),
//             and the client-side block proves the decision took effect on the wire.
//
// Run:  BIRDSHOT_EXTENSION_PATH=<...>/birdshot.duckdb_extension \
//         tsx birdshot/test/e2e/birdshot.e2e.ts
// (quack is not compiled into the C++ unittest binary, so this cannot live in
//  `make test`; it runs as `make test-e2e`. See README.)

import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { resolve, dirname } from "node:path";
import { DuckDBInstance } from "@duckdb/node-api";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXT =
  process.env.BIRDSHOT_EXTENSION_PATH ??
  resolve(HERE, "../../build/release/extension/birdshot/birdshot.duckdb_extension");
const DOT_TEST = resolve(HERE, "../sql/birdshot.test");

const q = (s: string) => "'" + s.replace(/'/g, "''") + "'";
const b64url = (s: string) =>
  Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const devJwt = (sub: string) => `${b64url('{"alg":"none","typ":"JWT"}')}.${b64url(JSON.stringify({ sub }))}.x`;
const b64urlDecode = (s: string) =>
  s ? Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8") : "";

const ALICE = devJwt("alice"); // sess1/sess2 in the .test (reader role)
const BOB = devJwt("bob"); //   bsess in the .test (colrole, columns {c1,c2})

// ---- result accounting ------------------------------------------------------
let passed = 0;
const failures: string[] = [];
function check(ok: boolean, label: string, detail = "") {
  if (ok) { passed++; return; }
  failures.push(`${label}${detail ? `  — ${detail}` : ""}`);
  console.log(`  ✗ ${label}${detail ? `  — ${detail}` : ""}`);
}

function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => { const p = (s.address() as any).port; s.close(() => res(p)); });
  });
}

interface AuditEntry { event: string; decision: string; reason: string; query: string }
async function drain(conn: any): Promise<AuditEntry[]> {
  const blob = ((await conn.runAndReadAll("SELECT birdshot_log_drain(10000) AS blob")).getRowObjects()[0]?.blob as string) ?? "";
  return blob.split("\n").filter(Boolean).map((line) => {
    const [, event, , , decision, reasonB64, queryB64] = line.split("\t");
    return { event, decision, reason: b64urlDecode(reasonB64), query: b64urlDecode(queryB64) };
  });
}

// ---- .test parser -----------------------------------------------------------
// Extract every `SELECT birdshot_authorize('<sid>', '<query>');` assertion with
// its expected boolean, plus the line index (to detect the revocation region).
interface Assertion { sid: string; query: string; expect: boolean; line: number }
function parseAuthorizeAssertions(): { assertions: Assertion[]; revokeLine: number; drainLine: number } {
  const lines = readFileSync(DOT_TEST, "utf8").split("\n");
  const re = /^SELECT birdshot_authorize\('([^']*)', '(.*)'\);$/;
  const out: Assertion[] = [];
  let revokeLine = Infinity, drainLine = Infinity;
  for (let i = 0; i < lines.length; i++) {
    // Match the STANDALONE revoke/drain statements that bracket the revocation
    // region — NOT the `birdshot_revoke(...)`/`...drain(...)` text that appears
    // INSIDE an authorize() test argument (those are authorize assertions, and
    // matching them would falsely swallow everything after into the region).
    if (revokeLine === Infinity && /^SELECT birdshot_revoke\(/.test(lines[i])) revokeLine = i;
    if (drainLine === Infinity && lines[i].includes("birdshot_log_drain(") && !lines[i].includes("birdshot_authorize(")) drainLine = i;
    const m = lines[i].match(re);
    if (!m) continue;
    // expected boolean: first `true`/`false` after the following `----`.
    let expect: boolean | null = null;
    for (let j = i + 1; j < lines.length; j++) {
      if (lines[j].trim() === "true") { expect = true; break; }
      if (lines[j].trim() === "false") { expect = false; break; }
      if (lines[j].startsWith("query ") || lines[j].startsWith("statement ")) break;
    }
    if (expect === null) continue;
    // un-double the SQL-escaped quotes to recover the real query text.
    out.push({ sid: m[1], query: m[2].replace(/''/g, "'"), expect, line: i });
  }
  return { assertions: out, revokeLine, drainLine };
}

// ---- run one verbatim (Form B) query as `identity`, return birdshot's verdict + client outcome
async function formB(srv: any, cliConn: any, uri: string, token: string, query: string) {
  let threw = false, rows = -1;
  try {
    rows = (await cliConn.runAndReadAll(
      `SELECT * FROM quack_query('quack:${uri}', ${q(query)}, token := '${token}', disable_ssl := true)`,
    )).getRowObjects().length;
  } catch { threw = true; }
  const log = (await drain(srv)).filter((l) => l.event === "authorize");
  // match the entry birdshot logged for THIS exact query (Form B logs it verbatim).
  const entry = [...log].reverse().find((l) => l.query === query) ?? log[log.length - 1] ?? null;
  return { decision: entry?.decision ?? null, reason: entry?.reason ?? "", threw, rows };
}

async function main() {
  const port = await freePort();
  const uri = `localhost:${port}`;

  // ---- SERVER -----------------------------------------------------------------
  const srvInst = await DuckDBInstance.create(":memory:", { allow_unsigned_extensions: "true" });
  const srv = await srvInst.connect();
  await srv.run(`LOAD ${q(EXT)}`);

  // Fixtures: both halves of the .test, all in memory.main.
  await srv.run("CREATE TABLE main.todos(id INT, title VARCHAR)");
  await srv.run("INSERT INTO main.todos VALUES (1,'a'),(2,'b')");
  await srv.run("CREATE TABLE secrets(id INT, title VARCHAR)");
  await srv.run("INSERT INTO secrets VALUES (9,'shh')");
  await srv.run("CREATE TABLE t(c1 INT, c2 INT, c3 INT, c4 INT, c5 INT GENERATED ALWAYS AS (c1 + 1))");
  await srv.run("INSERT INTO t(c1,c2,c3,c4) VALUES (1,2,3,4)");
  await srv.run("CREATE TABLE t2(c1 INT, c2 INT, c3 INT, c4 INT)");
  await srv.run("INSERT INTO t2 VALUES (1,2,3,4)");
  await srv.run("CREATE TABLE win_tbl(c1 INT, c2 INT)");
  await srv.run("INSERT INTO win_tbl VALUES (1,2)");
  // bind-and-walk regression-suite fixtures (struct, generated, ungranted).
  await srv.run("CREATE TABLE main.st(c1 INT, c2 INT, c3 STRUCT(f INT, g INT), c4 STRUCT(mid STRUCT(deeper INT)))");
  await srv.run("INSERT INTO main.st VALUES (1, 2, {'f':3,'g':4}, {'mid':{'deeper':5}})");
  await srv.run("CREATE TABLE main.gt(c1 INT, c2 INT, c3 INT, g_ok INT GENERATED ALWAYS AS (c1 + 1), g_bad INT GENERATED ALWAYS AS (c3 + 1))");
  await srv.run("INSERT INTO main.gt(c1,c2,c3) VALUES (1,2,3)");
  await srv.run("CREATE TABLE main.ungranted(c1 INT)");
  await srv.run("INSERT INTO main.ungranted VALUES (1)");

  // One combined snapshot (reader+colrole). Server config is global — there is no
  // mid-flight reset under a live client, so both identities' policy is pushed once.
  for (const s of [
    "SELECT birdshot_reset_config()",
    "SELECT birdshot_set_auth('', '', 'dev')",
    "SELECT birdshot_set_lake_catalog('memory')",
    "SELECT birdshot_add_role_grant('reader', 'main.todos', 'read')",
    "SELECT birdshot_add_user_role('alice', 'reader')",
    "SELECT birdshot_add_service_token('svc-token-123', 'alice')",
    "SELECT birdshot_add_role_grant('colrole', 'main.t', 'read')",
    "SELECT birdshot_add_role_grant('colrole', 'main.t2', 'read')",
    "SELECT birdshot_add_role_grant('colrole', 'main.win_tbl', 'read')",
    "SELECT birdshot_add_role_grant('colrole', 'main.t', 'write')",
    "SELECT birdshot_add_role_grant('colrole', 'main.t2', 'write')",
    "SELECT birdshot_add_role_grant('colrole', 'main.st', 'read')",
    "SELECT birdshot_add_role_grant('colrole', 'main.gt', 'read')",
    "SELECT birdshot_add_grant_constraint('colrole', 'main.t', 'c1,c2', '', '')",
    "SELECT birdshot_add_grant_constraint('colrole', 'main.win_tbl', '', '00:00', '23:59')",
    "SELECT birdshot_add_grant_constraint('colrole', 'main.st', 'c1', '', '')",
    "SELECT birdshot_add_grant_constraint('colrole', 'main.gt', 'c1,c2', '', '')",
    "SELECT birdshot_add_user_role('bob', 'colrole')",
    "SELECT birdshot_commit_config()",
  ]) await srv.run(s);

  await srv.run(`CALL quack_serve('quack:${uri}', token := 'srv-token')`);
  await srv.run("SET GLOBAL quack_authentication_function = 'birdshot_authenticate'");
  await srv.run("SET GLOBAL quack_authorization_function  = 'birdshot_authorize'");
  await drain(srv);
  console.log(`server up: quack:${uri}\n`);

  // A persistent Form-B client connection (quack_query carries its own token, so
  // one un-ATTACHed connection serves every identity).
  const fbInst = await DuckDBInstance.create(":memory:");
  const fb = await fbInst.connect();
  await fb.run("INSTALL quack; LOAD quack");

  // ================= BUCKET 1: replay every .test authorize assertion (Form B) =
  const { assertions, revokeLine, drainLine } = parseAuthorizeAssertions();
  const tokenFor: Record<string, string> = { sess1: ALICE, sess2: ALICE, bsess: BOB };
  const skipped: Array<{ a: Assertion; why: string }> = [];
  const replayed: Assertion[] = [];
  for (const a of assertions) {
    if (a.sid === "ghost") { skipped.push({ a, why: "unknown-session: quack only ever supplies a real authenticated sid; not expressible from a client" }); continue; }
    if (a.line > revokeLine && a.line < drainLine) { skipped.push({ a, why: "revocation-region: state-dependent, covered by the stateful revocation section below" }); continue; }
    if (/#\d/.test(a.query)) { skipped.push({ a, why: "positional `#N` push-down literal: covered authentically via the Form A scan section, not as a verbatim string" }); continue; }
    if (!tokenFor[a.sid]) { skipped.push({ a, why: `unmapped sid '${a.sid}'` }); continue; }
    replayed.push(a);
  }

  console.log(`=== Bucket 1: ${replayed.length} authorize assertions replayed end-to-end via Form B (quack_query) ===`);
  for (const a of replayed) {
    const r = await formB(srv, fb, uri, tokenFor[a.sid], a.query);
    const label = `[${a.sid}] ${a.query}`;
    if (a.expect) {
      check(r.decision === "allow" && !r.threw, `ALLOW ${label}`,
        r.decision !== "allow" ? `birdshot decision=${r.decision ?? "<none>"} (${r.reason})` : r.threw ? "client threw on an allowed query" : "");
    } else {
      // quack returns an error to the client on a deny, so enforcement == the
      // client threw. (decision=="deny" with rows back would be a wire data leak.)
      check(r.decision === "deny" && r.threw, `DENY  ${label}`,
        r.decision !== "deny" ? `birdshot decision=${r.decision ?? "<none>"} (${r.reason})` : `client NOT blocked (rows=${r.rows}) — DATA LEAK`);
    }
  }

  // ================= BUCKET 2a: Form A — authentic ATTACH+scan push-down ========
  // Real agent path: quack rewrites column projections to positional `#N`. Only
  // single-table-flat queries traverse this path (see multi-scan note up top).
  console.log(`\n=== Bucket 2a: Form A (real ATTACH + scan, bob/colrole) — #N push-down ===`);
  const bobInst = await DuckDBInstance.create(":memory:");
  const bobC = await bobInst.connect();
  await bobC.run("INSTALL quack; LOAD quack");
  await bobC.run(`ATTACH 'quack:${uri}' AS lake (TOKEN '${BOB}', DISABLE_SSL true)`);
  const formACases: Array<[string, boolean]> = [
    ["SELECT c1, c2 FROM lake.t", true], //                 -> #1,#2 allowed
    ["SELECT c1, c3 FROM lake.t", false], //                -> #1,#3 c3 forbidden
    ["SELECT c1, c2, c3, c4 FROM lake.t", false], //        -> #1..#4 c3,c4 forbidden
    ["SELECT * FROM lake.t", false], //                     -> #1..#5 (incl. generated c5)
    ["SELECT * FROM lake.t2", true], //                     unconstrained table
    ["SELECT * FROM lake.win_tbl", true], //                window grant, in-window
    ["SELECT c1 FROM lake.t WHERE c3 > 0", false], //       forbidden col hidden in WHERE
  ];
  for (const [Q, expect] of formACases) {
    let threw = false, rows = -1;
    try { rows = (await bobC.runAndReadAll(Q)).getRowObjects().length; } catch { threw = true; }
    const log = (await drain(srv)).filter((l) => l.event === "authorize");
    const decision = log.length ? log[log.length - 1].decision : null;
    if (expect) check(decision === "allow" && !threw, `ALLOW ${Q}`, decision !== "allow" ? `decision=${decision}` : threw ? "client threw" : "");
    else check(decision === "deny" && threw, `DENY  ${Q}`, decision !== "deny" ? `decision=${decision ?? "<none>"}` : `not blocked (rows=${rows})`);
  }

  // ================= BUCKET 2b: authentication (real ATTACH) ====================
  console.log(`\n=== Bucket 2b: authentication via real ATTACH ===`);
  // service token -> alice/reader.
  {
    const i = await DuckDBInstance.create(":memory:"); const c = await i.connect();
    await c.run("INSTALL quack; LOAD quack");
    let attached = true;
    try { await c.run(`ATTACH 'quack:${uri}' AS lake (TOKEN 'svc-token-123', DISABLE_SSL true)`); } catch { attached = false; }
    check(attached, "service-token ATTACH (svc-token-123 -> alice)");
    if (attached) {
      let ok = true; try { (await c.runAndReadAll("SELECT * FROM lake.todos")).getRowObjects(); } catch { ok = false; }
      await drain(srv);
      check(ok, "service-token reads granted main.todos");
      let blocked = false; try { (await c.runAndReadAll("SELECT * FROM lake.secrets")).getRowObjects(); } catch { blocked = true; }
      const dec = (await drain(srv)).filter((l) => l.event === "authorize").pop()?.decision;
      check(blocked && dec === "deny", "service-token denied ungranted secrets", dec !== "deny" ? `decision=${dec}` : "");
    }
  }
  // dev JWT (alice) authenticates.
  {
    const i = await DuckDBInstance.create(":memory:"); const c = await i.connect();
    await c.run("INSTALL quack; LOAD quack");
    let ok = true; try { await c.run(`ATTACH 'quack:${uri}' AS lake (TOKEN '${ALICE}', DISABLE_SSL true)`); } catch { ok = false; }
    check(ok, "dev-JWT ATTACH (alice)");
  }
  // garbage token rejected at ATTACH.
  {
    const i = await DuckDBInstance.create(":memory:"); const c = await i.connect();
    await c.run("INSTALL quack; LOAD quack");
    let rejected = false; try { await c.run(`ATTACH 'quack:${uri}' AS lake (TOKEN 'not-a-token', DISABLE_SSL true)`); } catch { rejected = true; }
    check(rejected, "garbage token rejected at ATTACH");
  }

  // ================= BUCKET 2c: instant revocation (stateful, Form B alice) =====
  console.log(`\n=== Bucket 2c: instant revocation cycle (alice) ===`);
  const beforeR = await formB(srv, fb, uri, ALICE, "SELECT * FROM main.todos");
  check(beforeR.decision === "allow" && !beforeR.threw, "alice reads todos (before revoke)");
  await srv.run("SELECT birdshot_revoke('user', 'alice', 'compromised', NULL)");
  const afterR = await formB(srv, fb, uri, ALICE, "SELECT * FROM main.todos");
  check(afterR.decision === "deny" && afterR.threw, "alice cut off on next query (revoked)",
    afterR.decision !== "deny" ? `decision=${afterR.decision}` : `not blocked (rows=${afterR.rows})`);
  await srv.run("SELECT birdshot_unrevoke('user', 'alice')");
  const afterU = await formB(srv, fb, uri, ALICE, "SELECT * FROM main.todos");
  check(afterU.decision === "allow" && !afterU.threw, "alice restored after unrevoke");

  // ================= census reconciliation =====================================
  console.log(`\n=== census ===`);
  console.log(`authorize assertions found in birdshot.test : ${assertions.length}`);
  console.log(`  replayed end-to-end via Form B            : ${replayed.length}`);
  console.log(`  skipped (covered elsewhere / by-nature)   : ${skipped.length}`);
  for (const s of skipped) console.log(`    - L${s.a.line + 1} [${s.a.sid}] ${s.a.query}\n        ${s.why}`);
  const accounted = replayed.length + skipped.length;
  check(accounted === assertions.length, "census reconciles (replayed + skipped == found)", `${accounted} != ${assertions.length}`);
  console.log(`additional e2e coverage: ${formACases.length} Form-A scan cases, 4 auth cases, 3 revocation cases`);

  // ---- summary ----------------------------------------------------------------
  const total = passed + failures.length;
  console.log(`\n${"=".repeat(60)}`);
  if (failures.length === 0) {
    console.log(`✅ ALL ${total} end-to-end checks PASSED`);
    process.exit(0);
  }
  console.log(`❌ ${failures.length}/${total} checks FAILED:`);
  for (const f of failures) console.log(`   - ${f}`);
  process.exit(1);
}

main().catch((e) => { console.error("HARNESS ERROR:", e); process.exit(1); });
