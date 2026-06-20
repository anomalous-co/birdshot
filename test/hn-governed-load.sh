#!/usr/bin/env bash
# Governed gateway-side ETL proof: drives birdshot_authorize() over the REAL HN
# CTAS in the production ref form, asserting the authorization DECISION that the
# governed-load endpoint relies on (authorize → execute-on-trusted-connection).
#
# This proves the NOVEL half (the decision). The durable write half is already
# proven by the gateway's /ctrl/load-hn (CTAS persists to lake.main via DuckLake).
#
# Why bare `main.hn_posts` (not `lake.main.hn_posts`): birdshot_set_lake_catalog
# makes BARE refs resolve INTO the lake for authz; the trusted exec connection has
# `USE lake`, so the same bare ref resolves into the lake for execution. Authz
# context ≡ execution context. An explicit `lake.` prefix would instead require a
# catalog-qualified grant — the compiler emits bare schema.table, so bare it is.
#
# Usage: test/hn-governed-load.sh [path/to/birdshot.duckdb_extension]
set -uo pipefail
cd "$(dirname "$0")/.."
EXT="${1:-$PWD/build/release/extension/birdshot/birdshot.duckdb_extension}"
DUCKDB="$PWD/build/release/duckdb"; [ -x "$DUCKDB" ] || DUCKDB="duckdb"
[ -f "$EXT" ] || { echo "extension not found: $EXT" >&2; exit 2; }

HNURL='https://hn.algolia.com/api/v1/search?tags=story&numericFilters=created_at_i>0&hitsPerPage=1000'
EVILURL='https://evil.example/x.json'

read -r -d '' SQL <<SQL
SET allow_unsigned_extensions=true;
LOAD '$EXT';
ATTACH ':memory:' AS lake;
SELECT birdshot_reset_config(); SELECT birdshot_set_auth('','','dev');
SELECT birdshot_set_lake_catalog('lake');
-- mirror the policy compiler: bare schema.table grants + a source allowlist.
SELECT birdshot_add_role_grant('agent','main.*','create');
SELECT birdshot_add_role_grant('agent','main.*','read');
SELECT birdshot_add_source_policy('agent','hn.algolia.com');
SELECT birdshot_add_user_role('pat','agent'); SELECT birdshot_add_service_token('tok','pat');
SELECT birdshot_add_user_role('np','nogrant'); SELECT birdshot_add_service_token('ntok','np');
SELECT birdshot_commit_config();
SELECT birdshot_authenticate('s','tok',''); SELECT birdshot_authenticate('n','ntok','');
.mode box
CREATE TEMP TABLE cases(scenario, expected, sess, q) AS SELECT * FROM (VALUES
 ('HN CTAS bare ref, allowlisted, granted',  true,  's', 'CREATE TABLE main.hn_posts AS SELECT * FROM read_json(''$HNURL'')'),
 ('HN CTAS bare ref, non-allowlisted host',  false, 's', 'CREATE TABLE main.hn_posts AS SELECT * FROM read_json(''$EVILURL'')'),
 ('HN CTAS bare ref, ungranted principal',   false, 'n', 'CREATE TABLE main.hn_posts AS SELECT * FROM read_json(''$HNURL'')'),
 ('HN CTAS http-not-https denied',           false, 's', 'CREATE TABLE main.hn_posts AS SELECT * FROM read_json(''http://hn.algolia.com/x'')'),
 ('HN CTAS non-const source (SSRF) denied',  false, 's', 'CREATE TABLE main.hn_posts AS SELECT * FROM read_json(concat(''https://hn.algolia.com/'',''x''))'),
 ('multi-statement rejected',                false, 's', 'CREATE TABLE main.hn_posts AS SELECT 1; DROP TABLE main.secrets')
) v;
SELECT scenario, expected, birdshot_authorize(sess,q) AS actual,
       CASE WHEN expected = birdshot_authorize(sess,q) THEN 'ok' ELSE '*** FAIL ***' END AS verdict FROM cases;
SELECT CASE WHEN count(*) FILTER (WHERE expected<>birdshot_authorize(sess,q))=0
  THEN 'HN GOVERNED-CTAS PROOF: ALL '||count(*)||' PASSED'
  ELSE 'HN GOVERNED-CTAS PROOF: '||count(*) FILTER (WHERE expected<>birdshot_authorize(sess,q))||' FAILED' END AS result FROM cases;
SQL

OUT=$("$DUCKDB" -unsigned -init /dev/null <<<"$SQL" 2>&1) || true
echo "$OUT" | grep -E 'scenario|HN CTAS|multi|verdict|PROOF|FAIL'
echo "$OUT" | grep -q 'PROOF: ALL' && { echo "[hn-governed-load] OK ($EXT)"; exit 0; } || { echo "[hn-governed-load] FAILED"; exit 1; }
