#!/usr/bin/env bash
# Full-scope capability ACL validation: loads the birdshot loadable extension
# (unsigned, exactly as the gateway does) and drives birdshot_authorize() across
# EVERY capability + grant mechanism, asserting each allow/deny decision.
#
# Usage:  test/validate-capabilities.sh [path/to/birdshot.duckdb_extension]
# Default extension: build/release/extension/birdshot/birdshot.duckdb_extension
# Requires a duckdb binary (uses build/release/duckdb, else `duckdb` on PATH).
#
# Reusable against any artifact: a local build, a CI-downloaded artifact, or one
# pulled from R2 (gunzip the .gz first). Exit 0 iff every scenario matches.
set -uo pipefail  # NOT -e: the duckdb CLI can exit nonzero on a benign dot-command,
                  # which must not abort the run; success is decided by the RESULT row.
cd "$(dirname "$0")/.."
EXT="${1:-$PWD/build/release/extension/birdshot/birdshot.duckdb_extension}"
DUCKDB="$PWD/build/release/duckdb"; [ -x "$DUCKDB" ] || DUCKDB="duckdb"
[ -f "$EXT" ] || { echo "extension not found: $EXT" >&2; exit 2; }

# A definitely-closed UTC window (30 min ahead) for the time-window deny test.
NOWMIN=$(( 10#$(date -u +%H) * 60 + 10#$(date -u +%M) ))
C1=$(( (NOWMIN + 30) % 1440 )); C2=$(( (NOWMIN + 31) % 1440 ))
CS=$(printf '%02d:%02d' $((C1/60)) $((C1%60))); CE=$(printf '%02d:%02d' $((C2/60)) $((C2%60)))

SQL=$(cat <<SQL
SET allow_unsigned_extensions=true;
LOAD '$EXT';
CREATE TABLE main.todos(id INT, title VARCHAR);
CREATE TABLE main.rw(id INT, title VARCHAR);
CREATE TABLE main.dropme(id INT); CREATE TABLE main.altme(id INT);
CREATE TABLE secrets(id INT, title VARCHAR); CREATE TABLE main.colcon(id INT, title VARCHAR);
CREATE TABLE main.win_open(id INT); CREATE TABLE main.win_shut(id INT);
SELECT birdshot_reset_config(); SELECT birdshot_set_auth('', '', 'dev');
SELECT birdshot_add_role_grant('power','main.todos','read');
SELECT birdshot_add_role_grant('power','main.rw','write');
SELECT birdshot_add_role_grant('power','main.dropme','drop');
SELECT birdshot_add_role_grant('power','main.altme','alter');
SELECT birdshot_add_role_grant('power','hn.*','create');
SELECT birdshot_add_role_grant('power','hn2','create');
SELECT birdshot_add_role_grant('power','mydb','detach');
SELECT birdshot_add_role_grant('power','main.colcon','read');
SELECT birdshot_add_role_grant('power','main.win_open','read');
SELECT birdshot_add_role_grant('power','main.win_shut','read');
SELECT birdshot_add_grant_constraint('power','main.colcon','id',NULL,NULL);
SELECT birdshot_add_grant_constraint('power','main.win_open',NULL,'00:00','23:59');
SELECT birdshot_add_grant_constraint('power','main.win_shut',NULL,'$CS','$CE');
SELECT birdshot_add_source_policy('power','data.example.com');
SELECT birdshot_add_dest_policy('power','out.example.com');
SELECT birdshot_add_ext_policy('power','birdshot');
SELECT birdshot_add_attach_policy('power','lake.example.com');
SELECT birdshot_add_user_role('pat','power'); SELECT birdshot_add_service_token('tok','pat');
SELECT birdshot_add_role_grant('wildcard','*','read');
SELECT birdshot_add_user_role('wild','wildcard'); SELECT birdshot_add_service_token('wtok','wild');
SELECT birdshot_commit_config();
SELECT birdshot_authenticate('s','tok',''); SELECT birdshot_authenticate('w','wtok','');
.mode box
CREATE TEMP TABLE cases(cap, sess, scenario, expected, q) AS SELECT * FROM (VALUES
  ('read','s','SELECT granted table',true,'SELECT id FROM main.todos'),
  ('read','s','SELECT ungranted table',false,'SELECT * FROM secrets'),
  ('read','s','ungranted in WHERE subquery',false,'SELECT * FROM main.todos WHERE id IN (SELECT id FROM secrets)'),
  ('write','s','INSERT write-granted',true,'INSERT INTO main.rw VALUES (1,''a'')'),
  ('write','s','UPDATE write-granted',true,'UPDATE main.rw SET title=''b'' WHERE id=1'),
  ('write','s','DELETE write-granted',true,'DELETE FROM main.rw WHERE id=1'),
  ('write','s','INSERT read-only',false,'INSERT INTO main.todos VALUES (1,''x'')'),
  ('write','s','write covers READ',true,'SELECT * FROM main.rw'),
  ('create','s','CREATE TABLE granted',true,'CREATE TABLE hn.x(id INT)'),
  ('create','s','CREATE TABLE ungranted',false,'CREATE TABLE other.x(id INT)'),
  ('create','s','CREATE SCHEMA granted',true,'CREATE SCHEMA hn2'),
  ('create','s','CREATE SCHEMA ungranted',false,'CREATE SCHEMA nope'),
  ('create','s','CREATE VIEW granted',true,'CREATE VIEW hn.v AS SELECT 1'),
  ('create','s','CREATE VIEW ungranted',false,'CREATE VIEW other.v AS SELECT 1'),
  ('create','s','CREATE INDEX fail-closed',false,'CREATE INDEX i ON hn.x(id)'),
  ('create','s','CTAS create+source ok',true,'CREATE TABLE hn.s AS SELECT * FROM read_csv(''https://data.example.com/x.csv'')'),
  ('create','s','CTAS source BLOCKED',false,'CREATE TABLE hn.s AS SELECT * FROM read_csv(''https://evil.example/x.csv'')'),
  ('create','s','CTAS create BLOCKED',false,'CREATE TABLE other.s AS SELECT * FROM read_csv(''https://data.example.com/x.csv'')'),
  ('create','s','CTAS from readable',true,'CREATE TABLE hn.copy AS SELECT id,title FROM main.todos'),
  ('create','s','CTAS from UNreadable',false,'CREATE TABLE hn.copy AS SELECT * FROM secrets'),
  ('drop','s','DROP with grant',true,'DROP TABLE main.dropme'),
  ('drop','s','DROP read-only (no drop)',false,'DROP TABLE main.todos'),
  ('alter','s','ALTER with grant',true,'ALTER TABLE main.altme ADD COLUMN c INT'),
  ('alter','s','ALTER read-only (no alter)',false,'ALTER TABLE main.todos ADD COLUMN c INT'),
  ('read_source','s','read_csv allowlisted',true,'SELECT * FROM read_csv(''https://data.example.com/x.csv'')'),
  ('read_source','s','read_json_auto allowlisted',true,'SELECT * FROM read_json_auto(''https://data.example.com/x.json'')'),
  ('read_source','s','read_parquet allowlisted',true,'SELECT * FROM read_parquet(''https://data.example.com/x.parquet'')'),
  ('read_source','s','allowlisted SUBDOMAIN',true,'SELECT * FROM read_csv(''https://sub.data.example.com/x.csv'')'),
  ('read_source','s','blocked host',false,'SELECT * FROM read_csv(''https://evil.example/x.csv'')'),
  ('read_source','s','http not https',false,'SELECT * FROM read_csv(''http://data.example.com/x.csv'')'),
  ('read_source','s','bare file path',false,'SELECT * FROM read_csv(''/etc/passwd'')'),
  ('read_source','s','non-const SSRF',false,'SELECT * FROM read_csv(concat(''https://data.example.com/'',''x''))'),
  ('copy_from','s','COPY FROM allowlisted->write',true,'COPY main.rw FROM ''https://data.example.com/x.csv'''),
  ('copy_from','s','COPY FROM ->read-only',false,'COPY main.todos FROM ''https://data.example.com/x.csv'''),
  ('copy_from','s','COPY FROM blocked',false,'COPY main.rw FROM ''https://evil.example/x.csv'''),
  ('copy_to','s','COPY readable TO allowlisted',true,'COPY (SELECT id FROM main.todos) TO ''https://out.example.com/o.csv'''),
  ('copy_to','s','COPY TO blocked dest',false,'COPY (SELECT id FROM main.todos) TO ''https://evil.example/o.csv'''),
  ('copy_to','s','COPY UNreadable TO',false,'COPY (SELECT * FROM secrets) TO ''https://out.example.com/o.csv'''),
  ('attach','s','ATTACH allowlisted',true,'ATTACH ''https://lake.example.com/db'' AS l'),
  ('attach','s','ATTACH blocked host',false,'ATTACH ''https://evil.example/db'' AS e'),
  ('attach','s','ATTACH bare path',false,'ATTACH ''evil.db'' AS x'),
  ('detach','s','DETACH with grant',true,'DETACH mydb'),
  ('detach','s','DETACH without grant',false,'DETACH otherdb'),
  ('install','s','INSTALL allowlisted',true,'INSTALL birdshot'),
  ('install','s','INSTALL blocked',false,'INSTALL httpfs'),
  ('install','s','LOAD allowlisted',true,'LOAD birdshot'),
  ('install','s','LOAD blocked',false,'LOAD httpfs'),
  ('pragma','s','PRAGMA denied',false,'PRAGMA enable_profiling'),
  ('pragma','s','SET denied',false,'SET threads=4'),
  ('column','s','allowed col bind-walk',true,'SELECT id FROM main.colcon'),
  ('column','s','forbidden col bind-walk',false,'SELECT title FROM main.colcon'),
  ('column','s','allowed col parse-path',true,'SELECT id FROM main.colcon, read_csv(''https://data.example.com/x.csv'')'),
  ('column','s','forbidden col parse-path',false,'SELECT title FROM main.colcon, read_csv(''https://data.example.com/x.csv'')'),
  ('window','s','inside open window',true,'SELECT id FROM main.win_open'),
  ('window','s','outside closed window',false,'SELECT id FROM main.win_shut'),
  ('wildcard','w','read * any table',true,'SELECT * FROM secrets'),
  ('wildcard','w','read * another table',true,'SELECT * FROM main.todos'),
  ('wildcard','w','read * not write',false,'INSERT INTO main.todos VALUES (1,''x'')')
) v;
SELECT cap, scenario, expected, birdshot_authorize(sess,q) AS actual,
       CASE WHEN expected = birdshot_authorize(sess,q) THEN 'ok' ELSE '*** FAIL ***' END AS verdict
FROM cases;
SELECT CASE WHEN count(*) FILTER (WHERE expected <> birdshot_authorize(sess,q)) = 0
            THEN 'RESULT: ALL ' || count(*) || ' PASSED' ELSE 'RESULT: ' ||
            count(*) FILTER (WHERE expected <> birdshot_authorize(sess,q)) || ' FAILED' END AS result
FROM cases;
SQL
)
OUT=$("$DUCKDB" -unsigned -init /dev/null <<<"$SQL" 2>&1) || true
echo "$OUT" | grep -E 'cap|verdict|FAIL|RESULT|todos|rw|colcon|win_|read|write|create|drop|alter|source|copy|attach|detach|install|pragma|column|window|wildcard' || true
if echo "$OUT" | grep -q 'RESULT: ALL'; then
  echo "[validate-capabilities] OK ($EXT)"
else
  echo "[validate-capabilities] FAILED"; echo "$OUT" | tail -30; exit 1
fi
