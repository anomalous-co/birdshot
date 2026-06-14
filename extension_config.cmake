# This file is included by DuckDB's build system. It specifies which extension to load.

# The birdshot extension from this repo.
duckdb_extension_load(birdshot
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
)

# birdshot's ACL parser relies on DuckDB's own SQL parser (built in core), and
# its host-side loader uses the postgres scanner to reach PGlite. No extra
# in-process extensions are required here; the host loads `postgres`/`quack`
# itself (see packages/db/src/stack.ts).
