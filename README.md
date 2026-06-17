# birdshot

A DuckDB C++ extension that implements [Quack](../docs/internal/duckdb/quack/)'s
two security hooks with real per-role table ACLs, query/violation logging, and
**instant revocation** — backed by [Better Auth](https://better-auth.com) for
OAuth user accounts and JWT token issuance.

birdshot replaces the stopgap `peer_read_only` macro in
`packages/db/src/stack.ts`. Full design:
[`docs/internal/duckdb/birdshot/design.md`](../docs/internal/duckdb/birdshot/design.md).

## How it fits

```
Better Auth (host, TS)  ──mints JWT / manages accounts──▶  authDb (isolated PGlite)
        │                                                      │ host loader reads
        │ OAuth, /api/auth/token, /api/auth/jwks               ▼ and PUSHES (birdshot_*)
        ▼                                            ┌───────────────────────────┐
   peer presents JWT or service token  ─ATTACH─▶ quack │ birdshot (in DuckDB, C++)│
                                                   hooks│  authenticate / authorize │
                                                        │  in-memory ACL + denylist │
                                                        └───────────────────────────┘
```

birdshot never opens a database connection. The host loader reads the isolated
`authDb` PGlite store and pushes a policy snapshot into the extension via the
`birdshot_*` functions below.

## SQL surface

| Function | Purpose |
| --- | --- |
| `birdshot_authenticate(sid, token, server_token) → BOOL` | quack auth hook: service-token or JWT → caches `sid → identity`. |
| `birdshot_authorize(sid, query) → BOOL` | quack authz hook: denylist + token expiry + per-table ACL, default-deny, logs. |
| `birdshot_reset_config()` / `birdshot_commit_config()` | Stage then atomically promote a new policy snapshot. |
| `birdshot_set_auth(issuer, audience, mode)` | `mode` ∈ `dev` \| `hs256` \| `rs256`. |
| `birdshot_set_secret(secret)` | HS256 / dev shared secret. |
| `birdshot_add_jwk(kid, n, e)` | RS256 public key (base64url modulus/exponent). |
| `birdshot_add_role_grant(role, table_ref, action)` | `action` ∈ `read` \| `write`; `table_ref` supports `schema.*` and `*`. |
| `birdshot_add_user_role(user_id, role)` | Map an identity to a role. |
| `birdshot_add_service_token(token, user_id)` | Static machine/peer credential (e.g. the quack federation token). |
| `birdshot_revoke(kind, id, reason, expires_us)` | Instant in-memory denylist add (`kind` ∈ `user` \| `jti` \| `session`). |
| `birdshot_unrevoke(kind, id)` | Lift a revocation. |
| `birdshot_log_drain(max_rows)` | Drain the audit ring (TSV; free-text fields base64url-encoded). |
| `birdshot_status()` | Snapshot counts for debugging. |

## Build

```bash
./setup-build.sh
# then point the host at the loadable:
export BIRDSHOT_EXTENSION_PATH="$(pwd)/build/release/extension/birdshot/birdshot.duckdb_extension"
```

The first build compiles DuckDB from source (slow). Requires cmake, ninja, a
C++17 compiler, and OpenSSL (vcpkg, or `OPENSSL_ROOT_DIR` for Homebrew OpenSSL).

Run the extension's own tests:

```bash
make test       # in-process: calls birdshot_authorize() directly (sqllogictest)
make test-e2e   # end-to-end: real quack client ↔ server, birdshot as the hooks
```

`make test` proves the *decision logic* — it calls `birdshot_authorize(sid, query)`
in-process and checks the boolean. `make test-e2e`
([`test/e2e/birdshot.e2e.ts`](test/e2e/birdshot.e2e.ts)) proves the decision is
actually *enforced on the wire*: it stands up a real quack server with birdshot
wired in as `quack_authentication_function` / `quack_authorization_function`
(exactly as `packages/db/src/birdshot.ts` does), connects real quack clients, and
replays every authorize assertion from `test/sql/birdshot.test` end-to-end. A deny
passes only if birdshot *logged* the deny (attribution) **and** the client was
actually blocked (enforcement) — so a "denied but rows came back" data leak fails
the test. (quack isn't compiled into the C++ unittest binary, so the e2e path runs
on the monorepo's Node runtime, not under `make test`; build the extension first.)

Two client paths are exercised:

- **Form B — `quack_query(uri, '<verbatim SQL>')`**: the whole statement runs
  server-side, so birdshot sees the exact query string. This carries the full
  matrix — joins, subquery-smuggle, CTEs, forbidden statements, file readers,
  casts (99 of the 108 `.test` assertions; the rest are an unknown-session check,
  two stateful-revocation steps, and `#N` literals covered by Form A).
- **Form A — `ATTACH 'quack:…'; SELECT cols FROM lake.t`**: the realistic agent
  path; quack pushes column projections down as positional `#N`. **Product
  limitation surfaced by the harness:** on this path quack cannot carry a `JOIN`
  or *any* cross-table / correlated subquery — it throws `Multiple streaming
  scans` *before birdshot runs*. So the ordinary ATTACH+scan path is
  single-table-flat only; richer queries must go through `quack_query` (Form B).

## Status

- **Compiles** against DuckDB v1.5.3 (`./setup-build.sh`, OpenSSL via brew).
- **`make test` passes** — 159 assertions: configure → authenticate (service token
  + dev JWT + reject) → authorize (per-table ACL, write-vs-read, forbidden
  statements, subquery-smuggle, batch-smuggle, birdshot-mutator calls,
  file/dynamic readers, EXPLAIN ANALYZE, **PRAGMA, autoload-type casts**) →
  instant revocation → audit drain.
- **`make test-e2e` passes** — 115 end-to-end checks: 99 `.test` authorize
  assertions replayed through a real quack client→server (Form B), plus Form-A
  `#N` push-down, service-token / dev-JWT / bad-token auth, and the instant
  revocation cycle. Verdicts are taken from birdshot's own audit log AND the
  client-side block, so a denial that still leaks rows fails.
- **Live two-instance federation verified** — both instances peer each other
  through birdshot's hooks (`peer_connected=true`, cross-instance reads). The
  quack ATTACH handshake (introspection) passes the stricter authorize; only real
  data queries are ACL'd (design open item #2 resolved empirically).
- **Live instant revocation verified** — `birdshot_revoke('user','peer')` on the
  server cuts off a connected client on its next query (`Authorization failed`)
  and blocks re-ATTACH.
- `pnpm --filter @pglite-sandbox/db typecheck` is green; `BIRDSHOT_EXTENSION_PATH`
  is wired into the root `dev:a`/`dev:b` scripts.

Not yet exercised live: the RS256 path against a running Better Auth JWKS
(`dev`/`hs256` are covered), and a full user OAuth→JWT→peer flow (needs
`pnpm --filter web add better-auth pg` + schema generation). The legacy
`peer_read_only` macro remains as an automatic fallback when the extension
isn't built/loadable.
