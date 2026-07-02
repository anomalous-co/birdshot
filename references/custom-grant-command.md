# Custom SQL commands via the DuckDB extension API — feasibility for `GRANT … TO <token>`

Research note. Answers: *can birdshot expose a real `GRANT <access> ON <table> TO <token>` statement
instead of the current `birdshot_*` scalar-function push?*

## TL;DR

**Yes.** DuckDB's extension API has a first-class hook for adding brand-new SQL statements —
`ParserExtension` (`duckdb/src/include/duckdb/parser/parser_extension.hpp`). `GRANT` is a
keyword token in the vendored Postgres grammar **but has no production rule**, so `GRANT …`
fails the built-in parser and is handed to registered parser extensions. Verified empirically:

```
$ echo "GRANT SELECT ON t TO alice;" | duckdb
Parser Error: syntax error at or near "GRANT"
```

That "fails the built-in parser" is exactly the precondition a `ParserExtension` needs. A working
reference implementation of a custom statement lives in-tree:
`duckdb/test/extension/loadable_extension_demo.cpp` (the `QUACK` command).

## What the extension API lets you add

| Mechanism | Adds | birdshot uses it? |
|---|---|---|
| Scalar / aggregate / table functions | `foo(...)` callables | **Yes** — all 20 `birdshot_*` fns |
| **`ParserExtension`** (`parse_function` + `plan_function`) | **new top-level statements** (`GRANT …`, `REVOKE …`) | no (this note) |
| `parser_override` | replace the whole parser for a query | no |
| `PlannerExtension` (`post_bind_function`) | rewrite bound plans | no |
| `OperatorExtension` / optimizer extension | custom logical/physical ops, rewrite rules | no |
| `StorageExtension` | custom catalogs / attach backends | no |
| Custom types + cast functions | new `LogicalType`s | no |

You **cannot** add new *keywords* or grammar productions to the built-in Bison grammar from an
extension (the grammar is generated at DuckDB build time). Custom statements work precisely because
they ride the "built-in parser failed → ask the extensions" fallback.

## How a `ParserExtension` statement flows

`duckdb/src/parser/parser.cpp` (~L290–356) + `duckdb/src/planner/binder/statement/bind_extension.cpp`:

1. DuckDB parses the whole SQL string with its Postgres parser. On success, extensions are **never
   consulted** — this is why the target syntax must not already parse. (`GRANT` qualifies.)
2. On failure, DuckDB `SplitQueries()` on `;` and, per statement, calls each extension's
   `parse_function(info, query) -> ParserExtensionParseResult`:
   - `PARSE_SUCCESSFUL` + `ParserExtensionParseData` → wraps it in an `ExtensionStatement`.
   - `DISPLAY_EXTENSION_ERROR` → surface my error (e.g. "Did you mean GRANT … TO?").
   - `DISPLAY_ORIGINAL_ERROR` → not mine, fall through to the next extension / original error.
3. At bind time `Binder::Bind(ExtensionStatement&)` calls `plan_function(info, ctx, parse_data)
   -> ParserExtensionPlanResult`, which hands back a **`TableFunction`** + `parameters`. The
   statement is planned as a scan of that table function. `modified_databases`,
   `requires_valid_transaction`, and `return_type` are set here.
4. The `TableFunction`'s `bind`/`function` callbacks run — that's where the **side effect** (mutate
   birdshot's `State`) happens, and where the result rows (e.g. one `'ok'`) are emitted.

So the shape is: **parse_function** (pure, string→struct) → **plan_function** (struct→TableFunction)
→ **table function body** (do the grant, return a status row).

## Registration (from the existing `ExtensionLoader` entrypoint)

The current entry is `DUCKDB_CPP_EXTENSION_ENTRY(birdshot, loader)` → `LoadInternal(loader)`.
Parser extensions register through `DBConfig`, reachable from the loader:

```cpp
auto &db     = loader.GetDatabaseInstance();
auto &config = DBConfig::GetConfig(db);
ParserExtension::Register(config, BirdshotGrantParser());   // sets parse_function/plan_function
```

(Pattern copied from `loadable_extension_demo.cpp` L612/L665–666.) This composes with the existing
`loader.RegisterFunction(...)` calls — keep the scalar fns and add the statement.

## Sketch for `GRANT <caps> ON <table> TO <token>`

```cpp
struct GrantParseData : ParserExtensionParseData {         // output of parse_function
  string caps, table_ref, token;                            // e.g. "read", "sales.orders", "<jwt sub>"
  unique_ptr<ParserExtensionParseData> Copy() const override { ... }
  string ToString() const override { ... }
};

// parse_function: hand-tokenize. Return DISPLAY_ORIGINAL_ERROR unless the statement starts
// with GRANT/REVOKE so unrelated syntax errors keep DuckDB's own message.
static ParserExtensionParseResult BirdshotGrantParse(ParserExtensionInfo*, const string &q);

// plan_function: return a table function that performs the mutation on execution.
static ParserExtensionPlanResult BirdshotGrantPlan(ParserExtensionInfo*, ClientContext&,
                                                   unique_ptr<ParserExtensionParseData> pd) {
  ParserExtensionPlanResult r;
  r.function = BirdshotGrantExecFunction();   // TableFunction whose body calls State::Get().Add*/Commit
  r.parameters = { Value(caps), Value(table_ref), Value(token) };
  r.requires_valid_transaction = false;
  r.return_type = StatementReturnType::QUERY_RESULT;   // emits one 'ok' row
  return r;
}
```

The table-function body maps directly onto today's setters: `GRANT read ON sales.orders TO alice`
≈ `birdshot_add_role_grant(role, 'sales.orders', 'read')` + `birdshot_add_user_role('alice', role)`
+ `birdshot_commit_config()`. (You'd fold role indirection in, or grant straight to the token/subject.)

## Caveats / decisions before building this

1. **Trust boundary — the important one.** Today's config push (`birdshot_add_*` + `commit`) runs on
   the **trusted host-loader path**, *not* on agent connections. A SQL `GRANT` travels the same quack
   wire as agent queries, so exposing it as a statement means deciding *who may run it*. Two facts
   help: (a) `birdshot_authorize`'s parse-walk pre-filter classifies anything that doesn't parse in
   DuckDB as `FORBIDDEN`/`PARSE_ERR` → **fail-closed deny**, so an agent issuing `GRANT` is already
   rejected unless you explicitly allow it; (b) you'd add an allow rule keyed on the authenticated
   session being an admin/control-plane identity. Do **not** let the `GRANT` statement bypass
   `birdshot_authorize`.
2. **Whole-string parse gate.** Extensions only fire when the *built-in* parse fails. A batch mixing
   valid DuckDB SQL + `GRANT` is handled by the per-`;`-statement `SplitQueries` fallback, but a
   `GRANT` with an embedded `;` in a quoted literal could be mis-split — keep the grammar simple and
   `;`-free in values.
3. **No transaction / catalog coupling.** `requires_valid_transaction = false` and don't touch the
   DuckDB catalog; birdshot state is a separate in-memory `State` singleton. `modified_databases`
   stays empty (read-only wrt DuckDB storage).
4. **WASM.** Parser extensions are plain C++ compiled into the same artifact; the `wasm_*` targets
   build identically. No extra loader wiring, but re-test the `LOAD birdshot` path in duckdb-wasm.
5. **Ergonomics only.** This is a *surface* change, not a capability change — the enforcement engine
   (`Authorize`, grants/constraints/policies) is untouched. Value is a nicer admin UX and letting the
   control plane speak SQL DDL instead of function calls.

## Primary sources
- API: `duckdb/src/include/duckdb/parser/parser_extension.hpp`
- Dispatch: `duckdb/src/parser/parser.cpp` (~L290–356), `bind_extension.cpp`
- Reference impl: `duckdb/test/extension/loadable_extension_demo.cpp` (`QuackExtension` L198–277, `QuackFunction` L121–174, registration L612/L665)
- Grammar proof: no `grant.y` in `duckdb/third_party/libpg_query/grammar/statements/`; `GRANT` only a token in `kwlist.hpp`/`src_backend_parser_gram.cpp`
- Current birdshot surface: `src/birdshot_extension.cpp` (`LoadInternal` L1068)
