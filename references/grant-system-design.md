# birdshot GRANT system — full design spec

Builds on `references/custom-grant-command.md` (feasibility of a `ParserExtension`-backed `GRANT`
statement + the admin/agent trust boundary). This spec covers the **ambitious scope**:

1. **Full DML split** — `INSERT / UPDATE / DELETE / TRUNCATE` as distinct, distinctly-enforced caps
   (not collapsed to `WRITE`).
2. **Object classes** — `GRANT … ON SEQUENCE / FUNCTION / TYPE / DATABASE` (+ `SCHEMA`), enforced.
3. **Delegation** — `WITH GRANT OPTION`, `REVOKE … [CASCADE|RESTRICT]`, `REVOKE GRANT OPTION FOR`.

The parser is ~10% of this. The enforcement engine is the product. Two enforcement planes exist and
the work splits along them:

- **Parse-walk** (`src/birdshot_acl.hpp`) authorizes DDL / full-scope classes from the parse tree.
- **Bind-walk** (`src/birdshot_bind_analyze.hpp`) authorizes SELECT/DML + (new) runtime object use
  from the bound plan.

---

## 0. THE DECISION THAT GATES EVERYTHING — where authoritative grant state lives

birdshot `State` is an **in-memory singleton** in the gateway process, and it is a *projection* of
durable control-plane data. Every control-plane push runs `applySnapshot()`
(`packages/gateway/src/duck.ts:417`), which is **`birdshot_reset_config()` → add-all →
`birdshot_commit_config()`** (`duck.ts:423,455`; driven from `ctrl-server.ts:90`). Consequences that
are true regardless of deployment substrate:

- **Clobber**: any grant written into the gateway out-of-band is wiped by the next snapshot push
  (`reset_config` clears staging; `commit` replaces `live_`).
- **No durable re-materialization**: if the gateway process restarts, in-memory State is gone and is
  rebuilt *only* from the control-plane snapshot.

**REQUIREMENT (locked): birdshot is a self-contained authorization engine.** `LOAD birdshot` into
*any* DuckDB — a bare test DB, no control plane — and `GRANT SELECT ON t TO alice;` /
`REVOKE …` / `ALTER DEFAULT PRIVILEGES …` execute **in-process** and take effect immediately. All grant
logic lives in C++: parse, store, resolution (`ALL PRIVILEGES`, `ALL … IN SCHEMA`, `PUBLIC`,
`CURRENT_USER`, role membership, default-privilege templates), delegation `grant_option`, and cascade
`REVOKE`. The control plane is **not** required for correctness — it is at most an optional admin
client that issues the same statements.

The earlier "control-plane compiles and pushes" framing was wrong: it let ONE waddling-gateway detail
(`applySnapshot` does `reset→add→commit`, so a naive push clobbers) dictate the engine's location. That
is an *integration* concern, fixed by making the gateway reconcile instead of blind-clobber — not a
reason to export the engine.

**Decision (2026-07-02, revised) → birdshot OWNS the grant engine in C++; the grant STORE is a
PLUGGABLE BACKEND, programmatically re-pointable at runtime.** The engine (parse, resolve, enforce,
cascade) never moves; only *where the grant rows live* is configurable. And every backend is the same
thing to DuckDB — **a `grants` table in some ATTACHed catalog** — so one code path covers all three:

| Backend | ATTACH target | Use |
|---|---|---|
| **In-memory** | none (`State` only) | tests / bare standalone — immediate, gone on exit |
| **Local table** | `:memory:` / a DuckDB file | single-node durability, no network |
| **Remote over quack** | `quack:host` | a table served by another DuckDB endpoint |
| **Transactional Postgres** | `postgresql://…` `(TYPE postgres)` | **production**: ACID grant store over the network |

- **`State` is the in-memory read model; the backend is durable truth.** Enforcement (hot path) always
  reads `State` — never a network round-trip per query. A GRANT/REVOKE is a **transactional
  write-through**: mutate the backend inside a transaction, and on commit update `State`. On the
  transactional-Postgres backend that transaction is a real PG transaction (DuckDB's `postgres`
  extension propagates BEGIN/COMMIT), so concurrent GRANT/REVOKE and cascade get ACID + durability +
  concurrency for free — which is exactly why "grants are highly transactional" wants this backend.
- **Programmatic pointing**: a birdshot config function selects the backend at runtime and accepts a
  DSN / credentials, e.g. `birdshot_set_grant_store('postgres', '<dsn>')` /
  `birdshot_set_grant_store('local')`. Because production uses an **on-the-fly, narrowly-scoped psql
  login** (can touch only this org's grant tables), the config must accept **rotating** credentials
  and reconnect on expiry. The scoped login is defense-in-depth: even a store-logic bug can't reach
  other data. Fits the existing managed-Postgres + `credops.sh` rotation model (CLAUDE.md).
- **Delegation + cascade stay in C++, backend-agnostic**: `grant_option` on each row; cascade `REVOKE`
  is a DFS over `grantor→grantee` edges computed in C++ from `State`, then the resulting deletes are
  issued as **one transaction** against the backend. (Alternatively model a self-FK `ON DELETE
  CASCADE` in the PG schema and let PG do it — cleaner on PG, but the C++ DFS keeps identical behavior
  across all backends. Recommend C++ DFS.)
- **Production waddling**: no control plane in the grant path at all — birdshot talks to the
  transactional PG store directly. The old `applySnapshot` becomes, at most, a bulk admin-authoring
  client; it no longer owns durability.

> Rejected — exporting the engine to the control plane. Breaks standalone (can't GRANT on a bare/test
> DB) and is unnecessary: a pluggable backend gives networked transactional durability without moving
> the logic out of birdshot.

### Consistency: the cache-vs-transactional tension (matters for REVOKE)

Enforcement reads the in-memory `State` cache, but the backend is the transactional truth — so between
a committed REVOKE and a cache refresh there is a staleness window. For GRANT that's harmless
(under-grant, fails safe). **For REVOKE it fails OPEN** (access the admin believes is gone persists in a
stale cache) — the same asymmetry as §5, now across processes when several gateways share one PG store.
Mitigations, in increasing strength:

1. **Instant-deny bridge (reuse existing machinery):** a REVOKE also pushes the affected
   `(subject[, resource])` onto birdshot's existing instant-revocation denylist (`birdshot_revoke` →
   `deny_user_`, checked FIRST in `authorize`, `birdshot_extension.cpp:654`). This closes the window
   immediately, locally, before any cache refresh — the cache catches up behind it.
2. **Change signal:** a monotonic epoch column (or PG `LISTEN/NOTIFY`) the backend bumps on every
   mutation; each instance refreshes `State` when the epoch moves. Bounds cross-instance staleness to
   one poll interval / one notify latency.
3. **Read-through for the touched refs** only when strong consistency is required — slowest, reserve
   for high-assurance deployments.

Recommend **(1)+(2)**: instant-deny bridge for correctness on revocation, epoch/NOTIFY for steady-state
convergence. Decision surfaced in §7.

### The hard constraint: the grant store table must be UN-addressable by any token

Per "we can base it on a table; we just can't let any token access/control that table."
**Correction to a tempting shortcut:** do NOT reuse `IsSystemRef` (`acl.hpp:179`) — that flag means
*always-allowed* (system/introspection tables are skipped past the gate so quack's ATTACH handshake can
read `duckdb_tables()` etc.). Marking the grant table system would make it **world-readable** — the
opposite of the goal.

Introduce the **inverse**: `IsProtectedRef()` — a hard-**deny** set. Any wire query that references the
grant store in ANY plane is denied:
- **bind-walk** (`bind_analyze.hpp`): if any touched `BoundTableUse.ref` is protected → `forbidden`.
- **parse-walk** (`birdshot_acl.hpp`): CREATE/DROP/ALTER/COPY targeting a protected ref → `forbidden`
  (mirrors the existing `forbidden_drop_system` guard at `acl.hpp:802`).
- **The store catalog is protected too.** With a pluggable backend the store may be an ATTACHed
  catalog (`postgres`/`quack`/local). Its whole catalog goes in `IsProtectedRef` so no token can
  `SELECT`/`ATTACH`/address it — and the store's connection string / scoped psql login is
  birdshot-internal, never handed to a token and never reachable via agent `ATTACH` (already policy-
  gated). A token must not be able to point *its* session at the store, nor read it via the postgres
  scanner.
- Applies to **all** tokens, admin included — grants are changed only through `GRANT`/`REVOKE`
  statements (which birdshot executes internally against the backend), never by a client issuing raw
  DML at the table.
- The only ungated reader/writer is birdshot's own C++ (load, transactional write-through) on its
  internal store connection — not a client query.

Everything below assumes this in-C++ engine over a pluggable, protected, optionally-transactional store.

---

## 1. Model changes (shared foundation)

### 1a. Capability enum (`src/birdshot_state.hpp:48`)

Add the split DML caps and the object-use caps:

```cpp
enum class Capability : uint8_t {
  READ,                                  // SELECT
  WRITE,                                 // legacy umbrella — see Covers matrix
  INSERT, UPDATE, DELETE, TRUNCATE,      // NEW: split DML
  CREATE, DROP, ALTER,                   // catalog DDL
  USAGE,   // NEW: sequence nextval/currval, type use, schema use
  EXECUTE, // NEW: function/macro call
  READ_SOURCE, COPY_TO, ATTACH, DETACH, INSTALL, PRAGMA_SET,
  ADMIN,   // NEW: may run birdshot GRANT/REVOKE over the wire (see Phase 3 / trust boundary)
};
```

`ParseCapability` / `CapabilityName` (`state.hpp:77,93`) get the new spellings. **Keep fail-closed:
an unknown string returns false → under-grant.** The GRANT parser inherits this (see §4 rejection rule).

### 1b. Covers matrix (`state.hpp:64`) — back-compat is mandatory

Existing `write` grants (pushed today by `applySnapshot` / the policy compiler) must keep working, so
`WRITE` becomes an umbrella:

```
WRITE ⊇ { READ, INSERT, UPDATE, DELETE, TRUNCATE }     // legacy 'write' grant satisfies all DML
every fine-grained cap covers only itself (INSERT ⊉ UPDATE, etc.)
```

Migration story: an old `write` grant → satisfies all four DML caps + read. A new `GRANT INSERT`
grant satisfies *only* INSERT. Without the umbrella, the split is a silent regression that denies
formerly-allowed queries.

**LOCKED (2026-07-02): `UPDATE`/`DELETE` do NOT imply `READ` — PG-faithful/independent.**
`UPDATE t SET x=1 WHERE y>0` requires `UPDATE` *and* `SELECT`. The bind-walk already emits both a
`LOGICAL_UPDATE` (target) and a `LOGICAL_GET` (the WHERE scan), so the multi-cap model (§1d) expresses
`{UPDATE, READ}` naturally and the check requires both. Consequence to document for admins: a grantee
with *only* `update` and no `read` is denied on `UPDATE…WHERE`. (The legacy `WRITE` umbrella still
covers READ, so existing `write` grants are unaffected.)

### 1c. Object-kind discriminator — refs are no longer just names

Today a `Grant.resource_ref` is `[catalog.]schema.name` with **no object kind**, so a sequence `s` and
a table `s` collide. Add a kind to both the grant and the use:

```cpp
enum class ObjKind : uint8_t { TABLE, VIEW, SEQUENCE, FUNCTION, TYPE, SCHEMA, DATABASE };
struct Grant { ObjKind kind; std::string resource_ref; Capability cap; /* + grantor, grant_option (Phase 3) */ };
```

`RefMatch` gains a kind gate: a use of kind K against ref R is satisfied only by a grant of the same
kind (or a `DATABASE`/`SCHEMA` wildcard that dominates it — see §3). `DATABASE` maps to the catalog
component: `ON DATABASE d` ≈ wildcard ref `d.*` at `DATABASE` scope. `SCHEMA` ≈ `d.s.*`.

### 1d. Multi-cap-per-table (`BoundTableUse`, `bind_analyze.hpp:82`)

Replace the single `Capability cap` with a **set of required caps** per table (a table can require
several in one statement: `INSERT INTO t SELECT … FROM t` → `{INSERT, READ}`; `UPDATE t … WHERE` →
`{UPDATE, READ}`). The `touch()` merge (`bind_analyze.hpp:297`) unions the sets instead of promoting
toward WRITE. `BoundUseSatisfied` / `UseSatisfied` (`birdshot_extension.cpp:346,577`) must then check
**every** required cap is covered by some grant, not just one.

---

## 2. Phase 1 — DML split + object DDL grants  (trusted control connection only)

Contained; no wire-authorization work; agents stay safe-by-default (a wire `GRANT` still fails closed).

- **Bind-walk DML caps** (`bind_analyze.hpp:123-157`): the three operators already exist. Give each
  its own cap — `LOGICAL_INSERT`→INSERT, `LOGICAL_UPDATE`→UPDATE, `LOGICAL_DELETE`→DELETE — instead
  of the shared `AddWriteTable(..., WRITE)`. Feed the multi-cap set from §1d.
- **TRUNCATE — VERIFY FIRST**: confirm whether DuckDB surfaces `TRUNCATE t` as a distinct bound
  operator or as a condition-less `LOGICAL_DELETE`. If indistinguishable at the plan level, TRUNCATE
  enforcement must come from **parse-tree detection** (statement/pragma form) instead of a bind-walk
  operator case. (Not a blocker for the rest of Phase 1.)
- **CREATE object types** (`acl.hpp:786-792`): currently `forbidden_create_type` (fail-closed) for
  INDEX/SEQUENCE/TYPE/MACRO. Extend the `CREATE_STATEMENT` dispatch to emit a `CREATE` cap_use for
  `CreateSequenceInfo` / `CreateTypeInfo` / `CreateMacroInfo` on their object refs, tagged with the
  right `ObjKind`. (INDEX stays deferred or maps to ALTER-on-its-table — decide.)
- **DROP/ALTER** (`acl.hpp:807,823`): already object-agnostic — they emit a cap_use on
  `catalog.schema.name` for any object. Thread `DropInfo.type` / the `AlterInfo` kind through
  `MakeCapUse` so the new `ObjKind` gate (§1c) matches correctly (so `DROP SEQUENCE s` needs a
  `drop` grant on *sequence* `s`, not table `s`).

## 3. Phase 2 — runtime USAGE / EXECUTE  (new bind-walk expression visitor)

Today `BoundAclVisitor` only collects base-table `LOGICAL_GET`s and `BoundColumnRefExpression`s
(`bind_analyze.hpp:104-191`). Sequences, functions, and types used *inside a query* are invisible.
Add expression-level visitation, fail-closed on any unresolvable ref exactly like tables:

- **`EXECUTE ON FUNCTION`**: visit `BoundFunctionExpression` → its function catalog entry → require
  `EXECUTE` on `(FUNCTION, catalog.schema.fn)`. (Scope: user/macro functions; built-in scalar
  functions are not gated — decide an allowlist so `SELECT lower(x)` isn't denied.)
- **`USAGE ON SEQUENCE`**: `nextval('s')` / `currval('s')` bind to a `BoundFunctionExpression` whose
  bind data points at the `SequenceCatalogEntry` → require `USAGE` on `(SEQUENCE, ref)`.
- **`USAGE ON TYPE`**: bound casts / column types referencing a user `LogicalType` → require `USAGE`
  on `(TYPE, ref)`.

`DATABASE` / `SCHEMA` grants act as dominating wildcards over the objects they contain (§1c), so
`GRANT USAGE ON DATABASE d TO x` covers every object-use in `d`. CONNECT-style database access (may I
attach/open `d` at all) is already governed by birdshot's ATTACH policy at connect time — reuse it.

## 4. Phase 3 — delegation  (all in C++)

- **`Grant` gains `grantor` + `grant_option`** (§1a/§1c) so enforcement can answer "does this subject
  hold (object, cap) WITH grant option?".
- **Two execution paths, one store.** A `GRANT`/`REVOKE` runs either:
  - **Trusted/local (test DB, admin console, gateway's own connection):** executes unconditionally —
    whoever holds the connection is the authority. This is the standalone path — a developer on a bare
    DuckDB just runs it.
  - **Untrusted wire (a token delegating what it holds):** must be *authorized* first. Once the
    ParserExtension is registered, `GRANT …` parses into a `StatementType::EXTENSION_STATEMENT`;
    `Analyze()` has no case for it → fails closed (tokens safe by default). To *allow* a delegator,
    add an explicit `EXTENSION_STATEMENT` case that (a) recognizes it as a birdshot GRANT, (b) parses
    the target `(object, cap, grantee)`, (c) checks the **session identity** holds that `(object,
    cap)` WITH `grant_option` (or `ADMIN`), (d) allows only then. The ParserExtension can't see the
    `sid` from `ClientContext`, so `authorize` is the sole chokepoint — safe because quack runs it
    before execution.
- **On allow, birdshot mutates its own store** (in-memory `State`, persisted to the protected table
  if configured — §0). The edge `(grantor, grantee, obj_kind, ref, cap, grant_option)` is added
  in-process; no external round-trip.
- **`REVOKE … [CASCADE|RESTRICT]` + `REVOKE GRANT OPTION FOR`**: a **DFS in C++** over the store's
  `grantor→grantee` edges — collect dependents, delete the subtree on CASCADE, block on RESTRICT if
  dependents exist, or strip only the option on `GRANT OPTION FOR`. Ordinary graph work over the
  in-memory adjacency; persist the result if the store is backed.

This keeps delegation entirely inside birdshot: the store is the truth, the DFS is a dozen lines, and
it works identically on a bare test DB and behind the gateway.

---

## 5. Grammar surface — accept the full PostgreSQL surface (all in C++)

**Goal: accept as much of the real PostgreSQL `GRANT` / `REVOKE` / `ALTER DEFAULT PRIVILEGES` grammar
as possible.** This is achievable *without* bloating the enforcer by separating the *resolution* of
high-level constructs from the *checking* of concrete grants. **All three layers are in birdshot C++**
(§0); the control plane, if present, is just another client that issues these statements.

```
 [ AUTHORING ]  ParserExtension parse_function (C++)
   The ENTIRE PG grammar: all privileges, all object classes, ALL … IN SCHEMA,
   column lists, role_specification (PUBLIC/CURRENT_USER/…), GRANTED BY,
   WITH GRANT/ADMIN/INHERIT/SET OPTION, CASCADE/RESTRICT, ALTER DEFAULT
   PRIVILEGES, role membership.
        |
        v
 [ RESOLUTION ]  birdshot C++, at GRANT/REVOKE execution time
   Expand/resolve to CONCRETE grant rows in the in-C++ store:
     - roles / PUBLIC / CURRENT_USER  -> concrete grantee subjects
     - ALL TABLES IN SCHEMA / ON DATABASE -> wildcard refs (s.* / d.*); RefMatch
       already handles wildcards
     - ALL PRIVILEGES -> the object class's full applicable cap set
     - ALTER DEFAULT PRIVILEGES -> materialize on CREATE (birdshot sees CREATEs)
     - delegation (grantor/grant_option) + cascade REVOKE (DFS over the store)
        |
        v
 [ ENFORCEMENT ]  birdshot C++
   Checks concrete grants + wildcard RefMatch at the parse/bind walk.
   Grows a Capability ONLY where a real enforcement point exists.
```

So "how much of Postgres can we support?" splits into two very different answers:
- **Authoring/round-trip fidelity: ~all of it.** The parser accepts it; birdshot stores it; it
  survives a `pg_dump`-style round-trip and shows up in the audit trail.
- **Behavioral enforcement: exactly the set with a real enforcement point** (the §8 matrix). Nothing
  else can change what a query is allowed to do.

### Revised fail-closed rule (supersedes the earlier "reject everything unenforceable")

This split lets us be more generous *without* the false-enforcement footgun, by
splitting "unenforceable" into two cases:

1. **Malformed / unknown privilege on a REAL, enforceable object** (e.g. a typo'd privilege on a
   table) → **hard parse error**. Never guess.
2. **A well-formed privilege that birdshot has no enforcement point for** (e.g. `TRIGGER` on a table,
   anything `ON TABLESPACE`) → **record it in the store flagged `enforced=false`, and emit an
   authoring-time WARNING** ("recorded for portability; birdshot does not enforce TRIGGER"). It is
   **never** the basis of an ALLOW — birdshot is default-deny and the enforcer never reads
   `enforced=false` rows — so it cannot create access. The warning is what keeps an admin from being
   misled; silence is the thing we forbid, not recording.

The original asymmetry still holds and still drives the rule: a dropped **GRANT** fails safe
(under-grant); a dropped **REVOKE** fails **open**. Recording-with-warning satisfies both — a REVOKE
of a non-enforced privilege is a no-op on something that was never enforcing, and it's logged, so
nothing silently retains access.

See §8 for the exhaustive privilege × object-class disposition and §9 for `ALTER DEFAULT PRIVILEGES`.

---

## 6. Phasing summary (ordered by blast radius)

| Phase | Scope | Where | Risk |
|---|---|---|---|
| 1 | DML split + object DDL grants + object-kind discriminator + multi-cap model + Covers matrix | bind-walk ops, parse-walk CREATE/DROP/ALTER, state.hpp enum | contained (trusted conn only) |
| 2 | runtime `USAGE`/`EXECUTE` (sequences, functions, types) | new bind-walk expression visitor | medium (new fail-closed walker) |
| 3 | delegation (`WITH GRANT OPTION`, cascade `REVOKE`) | parse-walk `EXTENSION_STATEMENT` gate + in-C++ grant graph (DFS) | all in C++; store persisted if configured |

## 7. Open decisions for product

1. ~~**UPDATE/DELETE imply READ?**~~ — **LOCKED**: PG-faithful/independent (§1b).
2. ~~**Where does the grant engine live?**~~ — **LOCKED**: entirely in birdshot C++; runs standalone
   on any DuckDB with no control plane. In-memory `State` is the store; optional persistence to a
   birdshot-owned protected table for durability (§0).
3. **Store backend + consistency** (§0) — confirm the pluggable-backend model (in-memory / local /
   quack / transactional Postgres) and the cross-instance consistency choice: instant-deny bridge +
   epoch/`LISTEN-NOTIFY` (recommended) vs. read-through. Also: config-function shape for runtime
   re-pointing + rotating scoped psql credentials.
4. **Built-in function allowlist** for `EXECUTE` (§3) — so `lower()`/`sum()` aren't gated.
5. **`CREATE INDEX`** — its own cap on the index, or `ALTER` on the underlying table? (§2)
6. **Grantee default** — `TO <token>` grants to subject vs. force explicit roles? (§5)
7. **Record-vs-reject line** — confirm the §5 revised rule: record-with-warning for well-formed
   non-enforced privileges (portability) vs. the stricter hard-reject. (Recommend record-with-warning.)

---

## 8. Full privilege × object-class disposition

Legend — **Enforced** (real enforcement point in the parse/bind walk) · **Map** (to an existing
birdshot cap/policy) · **Record** (stored `enforced=false` + authoring warning; never an ALLOW) ·
**Reject** (hard parse error).

### 8a. Table / view privileges  (`ON [TABLE] t`, `ON ALL TABLES IN SCHEMA s`)

| PG privilege | birdshot | Status | Enforcement point |
|---|---|---|---|
| `SELECT` | `READ` | Enforced | bind-walk `LOGICAL_GET` |
| `SELECT (cols)` | `READ` + column allow-list | Enforced | bind-walk read-cols + `GrantConstraint` (`state.hpp:128`) |
| `INSERT` | `INSERT` | Enforced (Phase 1) | bind-walk `LOGICAL_INSERT` |
| `INSERT (cols)` | `INSERT` + column set | Enforced | INSERT target cols already collected (`bind_analyze.hpp:129`) |
| `UPDATE` | `UPDATE` (+`READ` if `WHERE`, §1b) | Enforced (Phase 1) | bind-walk `LOGICAL_UPDATE` |
| `UPDATE (cols)` | `UPDATE` + column set | Enforced | UPDATE SET cols already collected (`bind_analyze.hpp:147`) |
| `DELETE` | `DELETE` (+`READ` if `WHERE`) | Enforced (Phase 1) | bind-walk `LOGICAL_DELETE` |
| `TRUNCATE` | `TRUNCATE` | Enforced (Phase 1) | **verify** operator vs. cond-less DELETE (§2) |
| `ALL [PRIVILEGES]` | expand → all table caps | Enforced | compiler expansion |
| `REFERENCES` | (FK authority; no FK-create surface in the lake) | Record | — |
| `TRIGGER` | (DuckDB has no triggers) | Record | — |
| `MAINTAIN` (PG17) | (no VACUUM/ANALYZE grant surface) | Record | — |

### 8b. Object classes birdshot has a real surface for

| PG `ON …` | DuckDB reality | birdshot | Status |
|---|---|---|---|
| `SEQUENCE s` — `USAGE`/`SELECT`/`UPDATE` | sequences exist | `USAGE` on `(SEQUENCE, ref)` | Enforced (Phase 2, `nextval`/`currval` visitor). `SELECT`/`UPDATE` on a sequence → map to `USAGE` |
| `TYPE t` / `DOMAIN d` — `USAGE` | user types exist; domains ≈ types | `USAGE` on `(TYPE, ref)` (map DOMAIN→TYPE) | Enforced (Phase 2, cast/type visitor) |
| `FUNCTION`/`PROCEDURE`/`ROUTINE` — `EXECUTE` | macros/functions; `CALL` exists | `EXECUTE` on `(FUNCTION, ref)` | Enforced (Phase 2). Overload signature `f(argtypes)` → key on name (+optional signature) |
| `SCHEMA s` — `USAGE` | schemas exist | `USAGE` on `(SCHEMA, s)` — dominates objects in `s` | Enforced (wildcard) |
| `SCHEMA s` — `CREATE` | `CREATE … IN s` | `CREATE` scoped to schema | Enforced (parse-walk CREATE) |
| `DATABASE d` — `CONNECT` | attach/open a catalog | `ATTACH` policy / connect gate | Map (existing attach policy) |
| `DATABASE d` — `CREATE` | create schema/objects in `d` | `CREATE` on `d.*` | Enforced (wildcard) |
| `DATABASE d` — `TEMP`/`TEMPORARY` | temp tables exist | `CREATE` on temp scope, or Record | Decide (lean Record) |
| `PARAMETER p` — `SET` | `SET`/`PRAGMA` | **`PRAGMA_SET`** (already exists!) | Enforced — direct map |
| `PARAMETER p` — `ALTER SYSTEM` | global `SET` | `PRAGMA_SET` (global scope) | Enforced / Map |

### 8c. Object classes with no DuckDB existence → Record (portability only, never an ALLOW)

`LARGE OBJECT`, `TABLESPACE`, `FOREIGN DATA WRAPPER`, `FOREIGN SERVER`, `LANGUAGE`. These name things
the lake/DuckDB does not have, so a query can never exercise them — recording is safe and lossless for
round-trip; enforcement is vacuous. (If you later map FDW/FOREIGN SERVER onto birdshot's
ATTACH/secret/extension policies, they graduate to **Map**.)

### 8d. Grantee resolution (`role_specification`) — compiler-side

| Form | Handling |
|---|---|
| `role_name` / `GROUP role_name` | role → `user_roles`; `GROUP` is legacy noise, strip it |
| `<token>` (subject) | grant straight to subject (auto singleton role) |
| `PUBLIC` | reserved pseudo-role every authenticated identity implicitly holds — real & useful (default-open for that one grant) |
| `CURRENT_USER` / `CURRENT_ROLE` / `SESSION_USER` | resolve to the **issuing session identity** at compile/authorize time (known for wire-issued GRANTs; the admin for control-plane GRANTs) |

### 8e. Role membership & options (`GRANT role TO x [WITH … OPTION]`)

| PG | birdshot |
|---|---|
| `GRANT r TO x` | `AddUserRole(x, r)` — already supported |
| `WITH ADMIN OPTION` | may re-grant the role → role-membership delegation (grant_option on the membership edge) |
| `WITH INHERIT OPTION` | birdshot **always inherits** (grants merge across a subject's roles, `GrantsForUser`) → INHERIT TRUE is the default; `INHERIT FALSE` → Record (no non-inheriting membership) |
| `WITH SET OPTION` | no `SET ROLE` over the quack wire → Record/Reject |

### 8f. Modifiers

- `WITH GRANT OPTION` → `grant_option` on the row; enables wire re-grant (Phase 3).
- `GRANTED BY role_specification` → sets the `grantor`; **validated** (you may only grant-by an
  authority you hold — admins, or self for what you hold `WITH GRANT OPTION`). Matters for `REVOKE`
  matching and cascade.
- `CASCADE | RESTRICT` (REVOKE) → grant-graph walk in the store (§Phase 3).
- `GRANT OPTION FOR` (REVOKE) → strip delegation right, keep the privilege.

## 9. `ALTER DEFAULT PRIVILEGES` — future-object templates

Semantics: "for objects **created in the future** by `target_role` in `schema`, auto-grant these
privileges to `grantee`." A template over not-yet-existent objects — and birdshot can do it **in C++**,
because it already observes every `CREATE` in the parse-walk:

- **Store**: a `default_privileges(for_role, in_schema, obj_kind, grantee, cap, grant_option)` rule
  set in `State` (persisted to the protected store if configured, §0).
- **Materialize on CREATE, in-process**: when birdshot authorizes a `CREATE` of an object of kind K in
  schema S by role R (it's right there in the parse-walk, `acl.hpp:755`), it also inserts the concrete
  grant rows for any matching default rule. Enforcement then only ever consults concrete grants — no
  object→creator provenance needed in the hot path.
- **`FOR ROLE`, `IN SCHEMA`, `ON TABLES/SEQUENCES/FUNCTIONS/TYPES/SCHEMAS`** become filters on the rule
  row. `ON LARGE OBJECTS` → Record (§8c).
- `REVOKE`-form removes a rule (future objects only; already-materialized grants unaffected, matching PG).

Fully expressible, entirely in the extension; the enforcer stays a concrete-grant checker. (A control
plane, if present, can still author these like any other statement — but nothing requires it.)

## 10. Implementation status & review outcomes (2026-07-02)

**Landed in the working tree (uncommitted), `make test` = 281 assertions green on a clean rebuild.**

Stage A (Phase 1) — COMPLETE: capability split (`INSERT/UPDATE/DELETE/TRUNCATE/USAGE/EXECUTE/ADMIN`),
`WRITE` umbrella Covers matrix, `ObjKind` discriminator (default TABLE), multi-cap-per-table
(`BoundTableUse.caps` set; every cap must be covered; empty → fail-closed), DML split in the bind-walk,
CREATE SEQUENCE/TYPE/MACRO, `IsProtectedRef` in both planes. Stage B — abstraction + `birdshot_set_grant_store()`
+ protection wiring landed; **transactional write-through/load deferred** (TODO in code, spec §0).

Findings from the advisor pass, and dispositions:
- **FIXED — `KindMatch` TABLE≡VIEW.** DROP/ALTER now carry the real object kind, but every legacy grant
  is TABLE-kind; without folding VIEW into the same "relation" class (spec §8a) a legacy `drop`/`alter`
  grant would silently stop covering a view. Latent today (the control-plane `role_grant.action` CHECK
  is `('read','write')` only — no drop/alter grants exist yet), but fixed now + regression-tested.
  `KindMatch` treats `{TABLE,VIEW}` as mutually covering; SEQUENCE/FUNCTION/TYPE stay strictly separate.
- **CARRY INTO STAGE B write-through** — name the store table `__birdshot_grants` (not just rely on the
  `__birdshot` *catalog alias*): the table-name prefix guard in `IsProtectedRef` then protects it even if
  the same physical DB is re-ATTACHed under a different alias. No live exposure today (write-through is a
  no-op; ATTACH is policy-gated; the psql login is scoped/secret) — but bake the naming in before wiring.
- **CARRY** — `birdshot_set_grant_store('table',…)` returns `'table'` though persistence is a no-op;
  return a distinct "configured, persistence-pending" status until write-through lands so operators
  aren't misled into thinking grants survive restart.
- **ACCEPTED, documented** — `duckdb_tables()`/`pragma_table_info` can reveal the store table's existence
  + column names (always-allowed introspection); data stays gated. Known, accepted leak.
- **Confirmed solid** (no action): multi-cap union+require-all+empty-fail-closed; `KindMatch` domination
  grant-side-only and still cap/ref-gated; `IsProtectedRef` denies (not skips) in both planes and beats a
  wildcard `*`; `WRITE` umbrella preserves exact legacy semantics; no lock nesting from `State::Get()` in
  `Analyze`; bare `DELETE`/`TRUNCATE` requiring `{DELETE,READ}` is stricter-than-PG but fail-safe.
- **TRUNCATE**: in DuckDB v1.5.3 `TRUNCATE t` parses to a `DeleteStatement` indistinguishable from an
  unconditioned `DELETE` (both → `LOGICAL_DELETE`); charged as `DELETE`. The `TRUNCATE` cap exists for
  GRANT-authoring fidelity + the umbrella but has no distinct enforcement point (documented).

**Build note**: the incremental build (Ninja) tracks `.hpp` → `.o` dependencies correctly via compiler
depfiles — verified empirically (touching `birdshot_state.hpp` recompiles `birdshot_extension.cpp.o`).
`make release && make test` after a header edit is sufficient; no forced object delete needed.

## 11. Phase 3a — native `GRANT`/`REVOKE` ParserExtension (2026-07-02)

**Landed in the working tree, `make test` = 324 assertions green.** The authoring surface: `GRANT …` /
`REVOKE …` execute as real SQL via a DuckDB `ParserExtension` — **no `birdshot_*` call** — mutating the
live store immediately, standalone (bare `LOAD birdshot`, no gateway). Delegation (`WITH GRANT OPTION`,
wire-authorized admin grants, cascade) remains Phase 3b; every wire GRANT is denied.

- **The security gate is parse-failure → deny (not the `EXTENSION_STATEMENT` case).** `Analyze` (the
  authorize pre-filter) builds a **bare `Parser`** with no extensions, so `GRANT …` throws in
  `ParseQuery` and is denied as `forbidden_grant_stmt` BEFORE any bind/plan/execution. The
  `EXTENSION_STATEMENT` case in `AnalyzeStatement` is defense-in-depth (fires only if `Analyze` ever
  becomes context-aware). Proven in-process: a wire GRANT is denied AND ineffective (the subsequent
  SELECT still denies); same for wire REVOKE.
- **Mutation only at execution.** `parse_function`/`plan_function`/table-function `bind` are
  side-effect-free; the store changes only in the exec `function` callback. `bind` staying pure is a
  **protected invariant** (commented in code): quack binds at PREPARE, before authorize denies — a
  mutation in `bind` would run pre-deny = critical bypass.
- **FIXED (advisor Finding A) — subject/role namespace collision.** `TO <subject>` now stores under a
  reserved-prefix self-role (`\x1d` + `subj:` + id) that admin role names can't collide with, closing
  an escalation where a JWT `sub` equal to a role name inherited that role's grants. Regression-tested.
- **Grammar**: supported — `GRANT/REVOKE <privs|ALL [PRIVILEGES]> ON [<kind>] <ref> TO/FROM <grantee>`
  (multi-grantee; `<grantee>` = subject or `ROLE r`), role membership `GRANT/REVOKE <role> TO/FROM x`.
  Deferred with a HARD error (never silent): column lists, `ALL … IN SCHEMA`, `PUBLIC`, `CURRENT_USER`,
  `WITH GRANT OPTION`, `GRANTED BY`, `CASCADE/RESTRICT`; unknown/unenforced privileges (TRIGGER/…) too.
- **`RevokeLive`** — birdshot's first removal primitive: erases grants whose `(ref, cap, kind)` exactly
  matches one `GrantLive` (exact ref, not `RefMatch`). Known: a kind-mismatched REVOKE (grant SEQUENCE,
  revoke default TABLE) removes nothing — consistent with the kind discriminator, vacuous today (only
  TABLE enforced), but Phase 2 must not inherit it as a silent hole.
- **Verification caveat (honest)**: enforcement is proven **in-process** (`make test`). Wire enforcement
  depends on quack calling `birdshot_authorize` before execution — proven for existing statement types
  by the e2e suite, but the GRANT path's wire deny is **not yet exercised by `make test-e2e`**. In-process
  verified; wire-enforced security pending an e2e case. The `bind`-purity invariant is what protects the
  wire path structurally in the meantime.

## 12. Grant store = raw GRANT SQL, lazy-hydrated, freshness-validated (2026-07-02, user-directed)

**User decisions (locked):** (1) agent grants are **raw GRANT SQL strings stored in a table birdshot
reads** — the table *is* the authority for roles/grants; (2) **lazy-pull** a token's grant strings from
the store the first time birdshot sees that token ("pull the correct grant strings for a token we
haven't seen yet"); (3) **validate freshness against the main DB on every authorization** — "check if
the grant has been changed; token roles must be valid and up to date"; (4) **drop time-of-day windows**
from birdshot enforcement. The control plane "only cares about grant SQL." This supersedes the scalar
`birdshot_add_role_grant` push for agent grants and builds on the §0 pluggable/protected store.

Design lens (user, verbatim): *"it's not about 'does anything do X' it's 'does X cause a bad state'."*
Each subsection below names the bad state it prevents.

### 12a. Storage form — raw GRANT SQL keyed by grantee  (bad state: subject collision / cross-lang drift)
Store table `__birdshot_grants` (protected — §0, §10). Cross-language contract (TS writer ⇄ C++ reader,
byte-for-byte):
- `grantee_kind TEXT` + `grantee TEXT` — the identity the statement targets, as an **explicit
  discriminator** (`'subject'` | `'role'` | `'public'`) plus the raw id. birdshot maps `(kind, grantee)`
  to its INTERNAL namespaced State key (`SubjectSelfRole(sub)` / bare role name / `PublicRole()`); the
  `\x1d` control bytes stay birdshot-internal and never appear in the store (so the table is
  human-readable, SQL-testable, and the TS writer needs no knowledge of the control-byte scheme). The
  discriminator is what prevents the Finding-A collision (a subject and a role sharing a name pull
  DISTINCT row sets: `WHERE grantee_kind='subject' AND grantee=?` vs `…='role'…`). Pull for a token =
  its `subject` rows ∪ `public` rows ∪ (transitively) each granted `role`'s rows.
- `stmt TEXT` — the raw `GRANT …` / `REVOKE …` string.
- `version BIGINT` (monotonic, bumped on every mutation) — the freshness signal (12d).
- optional `id`, `revoked_at` for soft-delete + cascade bookkeeping.

Storing SQL (not compiled `Grant` rows) means one parser+applier for both interactive and stored grants,
and the control plane authors exactly what birdshot enforces.

### 12b. Apply is PARSE-ONLY, never exec  (bad state: arbitrary SQL / DDL from a store row)
A pulled `stmt` goes through `BirdshotGrantParse` → `BirdshotApplyGrantOps` — the SAME native path as an
interactive GRANT. birdshot **never** `connection.run(stmt)`. A row that is not a clean GRANT/REVOKE
(parse error, or any non-grant statement) → the subject is **DENIED** (fail-closed), the row is NOT
skipped-and-continued. Even though only the control plane can write the store, birdshot treats `stmt` as
untrusted input: the worst a compromised/buggy row can do is express a well-formed grant — it can never
run DROP/DELETE/COPY on the agent connection.

### 12c. Lazy hydration fires at ATTACH, not inside authorize  (bad state: re-entrancy / deadlock / hot-path I/O)
The decisive choice (advisor Crux 1): hydration runs at the **quack ATTACH / `birdshot_authenticate`
handshake**, on birdshot's **trusted internal store connection**, NOT inside `birdshot_authorize`. A
store `SELECT` from inside authorize would hit the authorize hook that *protects* the store → deny or
infinite recursion. "A token we haven't seen" maps naturally to attach-time: pull once → populate
`State` → authorize stays a pure in-memory read.
- **Parameterized pull:** `SELECT stmt FROM __birdshot_grants WHERE grantee = ? [AND revoked_at IS NULL]`
  with a **bound parameter** — the token `sub` is attacker-controlled; never string-concat it. (Fallback
  if the internal-connection API can't bind against an ATTACHed postgres catalog: strict `sub`
  charset/length validation. Binding is the goal.)
- **Transitive role membership:** a pulled `GRANT <role> TO <subj>` adds a role; re-query for that
  role's `grantee` rows. **Bounded depth + cycle detection** — A∈B, B∈A must fail closed, not hang
  (availability bad state).
- **Apply keyed to the grantee NAMED in the stmt, never to the requesting session.** This is what makes
  a crafted `sub` non-catastrophic: even if it pulled extra rows, each applies to its own parsed
  grantee, so an attacker only benefits from rows that say `TO <attacker>`. Explicit invariant.
- **Fail-closed:** store unreachable / query error / any row won't parse → DENY the subject (never
  proceed on empty-or-partial).

### 12d. Freshness validation against the main DB  (bad state: stale REVOKE fails OPEN)
Requirement (user): the in-memory `State` is never trusted stale — birdshot validates that grants
haven't changed and roles are current. For GRANT staleness is harmless (under-grant); **for REVOKE it
fails OPEN** — the whole reason this is mandatory.
- **Epoch signal:** the store's monotonic `version` is bumped by the control plane on every mutation.
  birdshot records the version it hydrated a subject at.
- **Freshness gate on authorize:** if the store epoch has advanced past the subject's hydrated epoch,
  re-hydrate that subject before deciding. To keep this off a per-query round-trip, the epoch is read at
  a **bounded cadence** (cached ≤T, or driven by PG `LISTEN/NOTIFY`), so steady-state authorize stays
  in-memory and staleness is bounded to T. (Strong per-query validation is available as a high-assurance
  mode — §7 product decision on the T/round-trip trade-off.)
- **Instant-deny bridge for REVOKE:** a REVOKE also pushes the affected `(subject[,ref])` onto the
  existing instant-revocation denylist (checked FIRST in authorize), closing the window immediately and
  locally before the epoch catches up. This is what makes "up to date" real for revocation.
- **Token role validity:** role membership is part of the hydrated set and covered by the same epoch;
  token-level revocation/expiry stays on JWT `exp` + the instant-deny list.
- **Fail-closed on validation failure:** if the freshness check can't reach the store → DENY (a store
  outage denies queries — correctness over availability, accepted; a bounded last-known-good grace is a
  §7 option, default off).

### 12e. Drop windows  (bad state: silently widening a windowed grant to 24/7)
birdshot stops enforcing time-of-day windows; retire the window params of `birdshot_add_grant_constraint`
(columns stay — they live in the GRANT SQL and are enforced via the existing `gc`-constraint path).
**Before removing enforcement, confirm** the compile-time/JWT replacement actually gates time (like row
limits / `not_before` / `expires_at` already do) OR that no active rule uses a window to *restrict* —
otherwise a windowed grant silently becomes always-on.

### 12f. Control-plane rewrite — writes SQL, not tuples  (least security-critical; do LAST)
The control plane writes raw `GRANT`/`REVOKE` SQL rows into `__birdshot_grants` (transactional Postgres
store) and bumps `version`; it stops pushing `birdshot_add_role_grant` tuples for agent grants. Auth /
JWKS / lake-catalog setup may remain scalar config. The engine already works standalone without any of
this, so it is sequenced last.

### 12g. Phasing (advisor-sequenced; do NOT ship as one blob)
1. **RefMatch catalog-safe wildcards — DONE** (commit `0579dfc`).
2. **Store-holds-SQL + protection + trusted internal connection.** Prove `__birdshot_grants` and its
   catalog are unaddressable by any token in BOTH planes before anything reads them.
3. **Lazy hydration at attach** (12b/12c) — parameterized, parse-only, fail-closed, bounded recursion.
   Do NOT wire pull into live authorize until protection + parameterization + fail-closed are all in.
4. **Freshness gate** (12d) — epoch/NOTIFY + instant-deny bridge.
5. **Control-plane rewrite** (12f) + **drop windows** (12e).

## Primary sources
- Capability model / Covers / ParseCapability: `src/birdshot_state.hpp:48-108`
- Grant / GrantConstraint structs: `src/birdshot_state.hpp:118,128`
- Bind-walk (DML ops, expression visitor, multi-cap merge): `src/birdshot_bind_analyze.hpp:104-343`
- Parse-walk DDL dispatch (CREATE fail-closed at 786; DROP/ALTER generic): `src/birdshot_acl.hpp:755-824`
- Authorize (grant check + constraint enforcement): `src/birdshot_extension.cpp:630-809`
- Snapshot projection (clobber-replace): `packages/gateway/src/duck.ts:417-456`, `ctrl-server.ts:90`
- Custom-statement feasibility + trust boundary: `references/custom-grant-command.md`
