#pragma once

// In-memory state for the birdshot extension.
//
// birdshot never opens a database connection of its own. The TypeScript host
// loader reads the isolated `authDb` PGlite store and pushes a snapshot in via
// the config setter functions (see birdshot_extension.cpp). Everything here is
// process-global and guarded by a single shared_mutex so the quack auth/authz
// hooks (which run on fresh server-side connections, possibly concurrently)
// only ever do in-memory lookups.

// NOTE: the DuckDB extension build forces -std=c++11, so no std::shared_mutex
// (C++17). A plain std::mutex (all-exclusive) is used; the auth/authz hooks
// only ever do short in-memory lookups, so serializing them is fine.
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace birdshot {

// How presented JWTs are verified.
enum class AuthMode {
	DEV,    // decode claims WITHOUT signature verification (localhost/dev only)
	HS256,  // symmetric HMAC-SHA256 against `secret`
	RS256,  // asymmetric RSA-SHA256 against a JWKS public key
};

// One RSA public key from the JWKS (modulus/exponent, base64url as published).
struct JwkKey {
	std::string kid;
	std::string n_b64url; // modulus
	std::string e_b64url; // exponent
};

// ---- Capability enum -------------------------------------------------------
//
// Every distinct action birdshot can gate. READ/WRITE cover catalog table access
// (the original grant model). The remaining capabilities are vocabulary for
// non-catalog resource policies (URIs, extensions, ATTACH paths) that will be
// wired into the policy-check path in subsequent implementation chunks.
//
// Invariants enforced by Covers():
//   WRITE ⊇ { READ, INSERT, UPDATE, DELETE, TRUNCATE }  (legacy umbrella — back-compat)
//   Every fine-grained capability covers ONLY itself (INSERT ⊉ UPDATE, etc.).
//   LOCKED: UPDATE / DELETE do NOT imply READ — a query that both writes and reads
//   a table requires BOTH caps via the multi-cap model (PG-faithful, spec §1b).
//
// The Capability numeric value is NEVER serialized — grants round-trip as the
// string spellings via ParseCapability — so inserting new members anywhere is safe.
enum class Capability : uint8_t {
	READ,        // SELECT (catalog table)
	WRITE,       // legacy DML umbrella (see Covers) — pushed today by the policy compiler
	INSERT,      // INSERT (split DML)
	UPDATE,      // UPDATE (split DML) — independent of READ
	DELETE,      // DELETE (split DML) — independent of READ
	TRUNCATE,    // TRUNCATE — NOTE: in DuckDB v1.5.3 `TRUNCATE t` parses to a
	             // DeleteStatement indistinguishable from an unconditioned DELETE, so
	             // the enforcement point collapses to DELETE (see birdshot_bind_analyze).
	             // This cap exists for GRANT-authoring fidelity + the WRITE umbrella.
	CREATE,      // CREATE TABLE / VIEW / SCHEMA / SEQUENCE / TYPE / MACRO / CTAS target
	DROP,        // DROP
	ALTER,       // ALTER (+ CREATE INDEX on a table)
	USAGE,       // sequence nextval/currval, type use, schema use — Phase 2 (cap only now)
	EXECUTE,     // function / macro call — Phase 2 (cap only now)
	READ_SOURCE, // read_*/glob/COPY FROM source URI  — policy-gated, not RefMatch
	COPY_TO,     // COPY TO / EXPORT destination URI  — policy-gated
	ATTACH,      // ATTACH path/DSN                   — policy-gated
	DETACH,      // DETACH (catalog alias)
	INSTALL,     // INSTALL / LOAD extension name     — policy-gated
	PRAGMA_SET,  // SET / PRAGMA (deny-by-default allowlist)
	ADMIN,       // may run birdshot GRANT/REVOKE over the wire — Phase 3 (cap only now)
};

// True iff a grant with capability `g` covers a need for capability `u`.
// LOCKED semantics (spec §1b): the legacy WRITE umbrella covers READ + the four
// split DML caps so existing `write` grants don't regress; every fine-grained cap
// covers only itself. UPDATE/DELETE do NOT imply READ (independent, PG-faithful).
inline bool Covers(Capability g, Capability u) {
	if (g == u)
		return true;
	if (g == Capability::WRITE) {
		// Legacy umbrella: a `write` grant satisfies read + every split DML need.
		return u == Capability::READ || u == Capability::INSERT || u == Capability::UPDATE ||
		       u == Capability::DELETE || u == Capability::TRUNCATE;
	}
	return false; // all other capabilities are mutually exclusive
}

// ---- Object-kind discriminator --------------------------------------------
//
// A resource_ref is [catalog.]schema.name with NO object kind, so a sequence `s`
// and a table `s` would collide. ObjKind separates them. BACK-COMPAT: every
// existing grant/use predates this field and defaults to TABLE, so the entire
// legacy test suite (all TABLE grants over TABLE uses) is unaffected.
enum class ObjKind : uint8_t { TABLE, VIEW, SEQUENCE, FUNCTION, TYPE, SCHEMA, DATABASE };

// True iff a grant of kind `g` may satisfy a use of kind `u`. STRICT: exact match,
// EXCEPT (1) TABLE and VIEW are ONE "relation" class, and (2) a SCHEMA/DATABASE grant
// DOMINATES the objects it contains (spec §1c/§8a/§8b) — so `GRANT ... ON SCHEMA s`
// (kind SCHEMA) can cover a table/sequence use whose ref the grant's wildcard ref also
// matches. Domination is grant-side only: a TABLE grant NEVER covers a SEQUENCE use
// (that is the object-kind separation guarantee).
inline bool KindMatch(ObjKind g, ObjKind u) {
	if (g == u)
		return true;
	// TABLE ≡ VIEW (spec §8a groups table/view privileges). Required for back-compat:
	// every legacy grant is TABLE kind, and `DROP VIEW`/`ALTER VIEW` now carry VIEW
	// kind, so without this a legacy `drop`/`alter` grant would silently stop covering
	// a view (a test-invisible regression). Data reads never hit this — a view is not a
	// base-table GET (it expands to its underlying tables in the bind-walk), so VIEW
	// kind only arises for DDL naming the view object itself.
	if ((g == ObjKind::TABLE || g == ObjKind::VIEW) && (u == ObjKind::TABLE || u == ObjKind::VIEW))
		return true;
	return g == ObjKind::SCHEMA || g == ObjKind::DATABASE;
}

inline const char *ObjKindName(ObjKind k) {
	switch (k) {
	case ObjKind::TABLE:    return "table";
	case ObjKind::VIEW:     return "view";
	case ObjKind::SEQUENCE: return "sequence";
	case ObjKind::FUNCTION: return "function";
	case ObjKind::TYPE:     return "type";
	case ObjKind::SCHEMA:   return "schema";
	case ObjKind::DATABASE: return "database";
	}
	return "table";
}

// Parse an object-kind string (grant push path). Fail-closed on an unknown string:
// returns false so the caller drops the grant (under-grant is the safe direction),
// exactly like ParseCapability.
inline bool ParseObjKind(const std::string &s, ObjKind &out) {
	if (s == "table")    { out = ObjKind::TABLE;    return true; }
	if (s == "view")     { out = ObjKind::VIEW;     return true; }
	if (s == "sequence") { out = ObjKind::SEQUENCE; return true; }
	if (s == "function") { out = ObjKind::FUNCTION; return true; }
	if (s == "type")     { out = ObjKind::TYPE;     return true; }
	if (s == "schema")   { out = ObjKind::SCHEMA;   return true; }
	if (s == "database") { out = ObjKind::DATABASE; return true; }
	return false;
}

// Parse a capability string produced by the policy compiler / host snapshot push.
// Returns true and sets `out` on a recognized name. Returns false (fail-closed,
// do NOT grant anything) on an unknown string — under-grant is the safe direction.
// Spellings: the legacy `"read"` / `"write"` action strings from the existing
// birdshot_add_role_grant() callers must round-trip unchanged.
inline bool ParseCapability(const std::string &s, Capability &out) {
	if (s == "read")        { out = Capability::READ;        return true; }
	if (s == "write")       { out = Capability::WRITE;       return true; }
	if (s == "insert")      { out = Capability::INSERT;      return true; }
	if (s == "update")      { out = Capability::UPDATE;      return true; }
	if (s == "delete")      { out = Capability::DELETE;      return true; }
	if (s == "truncate")    { out = Capability::TRUNCATE;    return true; }
	if (s == "create")      { out = Capability::CREATE;      return true; }
	if (s == "drop")        { out = Capability::DROP;        return true; }
	if (s == "alter")       { out = Capability::ALTER;       return true; }
	if (s == "usage")       { out = Capability::USAGE;       return true; }
	if (s == "execute")     { out = Capability::EXECUTE;     return true; }
	if (s == "admin")       { out = Capability::ADMIN;       return true; }
	if (s == "read_source") { out = Capability::READ_SOURCE; return true; }
	if (s == "copy_to")     { out = Capability::COPY_TO;     return true; }
	if (s == "attach")      { out = Capability::ATTACH;      return true; }
	if (s == "detach")      { out = Capability::DETACH;      return true; }
	if (s == "install")     { out = Capability::INSTALL;     return true; }
	if (s == "pragma_set")  { out = Capability::PRAGMA_SET;  return true; }
	return false; // unknown capability string — reject (fail-closed)
}

// Return the canonical string name for a capability (for audit / status output).
inline const char *CapabilityName(Capability c) {
	switch (c) {
	case Capability::READ:        return "read";
	case Capability::WRITE:       return "write";
	case Capability::INSERT:      return "insert";
	case Capability::UPDATE:      return "update";
	case Capability::DELETE:      return "delete";
	case Capability::TRUNCATE:    return "truncate";
	case Capability::CREATE:      return "create";
	case Capability::DROP:        return "drop";
	case Capability::ALTER:       return "alter";
	case Capability::USAGE:       return "usage";
	case Capability::EXECUTE:     return "execute";
	case Capability::ADMIN:       return "admin";
	case Capability::READ_SOURCE: return "read_source";
	case Capability::COPY_TO:     return "copy_to";
	case Capability::ATTACH:      return "attach";
	case Capability::DETACH:      return "detach";
	case Capability::INSTALL:     return "install";
	case Capability::PRAGMA_SET:  return "pragma_set";
	}
	return "unknown";
}

// ---- Grant -----------------------------------------------------------------

// A single (resource, capability) permission attached to a role.
// `resource_ref` is a normalized catalog ref for READ/WRITE/CREATE/DROP/ALTER
// grants (lowercased "[catalog.][schema.]table" with optional trailing ".*" or
// bare "*" wildcards). For policy-gated capabilities (READ_SOURCE, COPY_TO,
// ATTACH, INSTALL, PRAGMA_SET) the `resource_ref` field is unused — those are
// controlled by the per-role ResourcePolicy lists in PolicySnapshot instead.
struct Grant {
	std::string resource_ref; // normalized ref (see above)
	Capability cap = Capability::READ;
	// Object kind this grant applies to. Defaults TABLE so every legacy grant
	// (pushed with no kind) keeps its exact current meaning. A use is satisfied
	// only by a grant whose kind KindMatch()es it (spec §1c).
	ObjKind kind = ObjKind::TABLE;
	// ---- delegation fields (spec §4/§8f) — STORED now, ENFORCED in Phase 3b ----
	// `grant_option` records `WITH GRANT OPTION`: the grantee may re-grant this
	// privilege. It is INERT today — there is no wire-authorized GRANT path yet, so
	// nothing consults it — but storing it is the round-trip/authoring deliverable.
	// `grantor` records `GRANTED BY <role>`. Also inert until cascade REVOKE (Phase
	// 3b) walks the grantor→grantee graph. Neither field participates in enforcement
	// (Covers/RefMatch/KindMatch), so a mis-set value can never over-grant.
	bool grant_option = false;
	std::string grantor;
};

// ---- reserved pseudo-role keys ---------------------------------------------
//
// The leading 0x1D (GROUP SEPARATOR) control byte can NEVER appear in an admin-
// defined role name (role names are SQL identifiers / compiler-generated) nor in a
// subject id used as a raw role key, so these reserved keys live in a keyspace that
// no real role or subject can collide with (same technique as SubjectSelfRole).
//
// PublicRole() is the pseudo-role every authenticated identity implicitly holds:
// `GRANT … TO PUBLIC` writes role_grants[PublicRole()], and GrantsForUser /
// ConstraintsForUser / *PoliciesForUser merge it in for EVERY user (spec §8d).
inline std::string PublicRole() {
	return std::string("\x1d") + "public";
}

// A finer-grained constraint attached to a role, scoped to one table. Layered on
// top of the coarse table grant above: a column allow-list and a UTC time window.
// (Row caps are NOT enforced by birdshot — a boolean authz hook can't truncate a
// result, and the LIMIT is stripped before the gateway ever sees a direct ref.)
// The sentinels mean "no restriction" so an entry can carry either dimension alone.
struct GrantConstraint {
	std::string table_ref;            // lowercased "schema.table"
	std::vector<std::string> columns; // lowercased allow-list; empty == unrestricted
	int32_t window_start_min = -1;    // minutes-of-day UTC; -1 == no window
	int32_t window_end_min = -1;      // minutes-of-day UTC; -1 == no window
};

// Verified caller identity, cached per quack session id at authentication time.
struct Identity {
	std::string user_id;
	std::string jti;
	int64_t exp_us; // token expiry, epoch microseconds; 0 == no expiry claim
};

// One audit record. Free-text fields are returned base64url-encoded by the
// drain function so the host never has to deal with delimiter escaping.
struct AuditEntry {
	int64_t ts_us;
	std::string event;    // "authenticate" | "authorize"
	std::string sid;
	std::string user_id;
	std::string decision; // "allow" | "deny"
	std::string reason;   // e.g. "ok", "bad_token", "revoked", "expired", "acl", "parse_error"
	std::string query;    // SQL text for authorize events, else ""
};

// ---- ResourcePolicy --------------------------------------------------------
//
// A single allowlist entry for non-catalog resource policies (URI sources/dest,
// extension names, ATTACH paths). The `pattern` semantics depend on which policy
// store the entry lives in — see UriPolicyMatch / ExtNameMatch / AttachTargetMatch
// in birdshot_acl.hpp for the per-store matching rules.
struct ResourcePolicy {
	std::string pattern; // host/suffix/glob/ext-name; exact semantics per matcher
};

// ---- PolicySnapshot --------------------------------------------------------

// The swappable policy snapshot. The host stages a new one via the setter
// functions and atomically promotes it with birdshot_commit_config().
struct PolicySnapshot {
	AuthMode mode = AuthMode::DEV;
	std::string issuer;
	std::string audience;
	std::string secret; // HS256 / dev shared secret (unused for RS256)
	std::vector<JwkKey> jwks;
	std::unordered_map<std::string, std::vector<std::string>> user_roles; // user_id -> role ids
	std::unordered_map<std::string, std::vector<Grant>> role_grants;      // role id -> grants
	std::unordered_map<std::string, std::vector<GrantConstraint>> role_constraints; // role id -> constraints
	// The catalog alias the lake is ATTACHed under (e.g. "lake"). The authz hook
	// runs on a fresh transient connection where the gateway's `USE <alias>` does
	// not carry over, so column positional resolution must name the catalog
	// explicitly. Empty == unset (fall back to the ref's own catalog/default path).
	std::string lake_catalog;
	// Static, long-lived credentials for machine/peer auth (e.g. the quack
	// federation token), checked before JWT verification. token -> user_id.
	std::unordered_map<std::string, std::string> service_tokens;

	// Per-role non-catalog resource policies. A use is satisfied iff the resource
	// literal matches at least one entry in the role's corresponding list. An
	// empty list means DENY (default-deny). These are additive across roles exactly
	// as role_grants are: the user's merged set is the union of all role entries.
	//
	//   source_policies  — READ_SOURCE: read_*/glob/COPY FROM URI
	//   dest_policies    — COPY_TO:     COPY TO / EXPORT destination URI
	//   ext_policies     — INSTALL:     INSTALL / LOAD extension name
	//   attach_policies  — ATTACH:      ATTACH path/DSN
	std::unordered_map<std::string, std::vector<ResourcePolicy>> source_policies;  // role -> []
	std::unordered_map<std::string, std::vector<ResourcePolicy>> dest_policies;    // role -> []
	std::unordered_map<std::string, std::vector<ResourcePolicy>> ext_policies;     // role -> []
	std::unordered_map<std::string, std::vector<ResourcePolicy>> attach_policies;  // role -> []
};

class State {
public:
	static State &Get() {
		static State instance;
		return instance;
	}

	// ---- config staging / promotion (host loader, write path) ----------------
	void ResetStaging();
	void SetAuth(const std::string &issuer, const std::string &audience, AuthMode mode);
	void SetSecret(const std::string &secret);
	void AddJwk(const std::string &kid, const std::string &n_b64url, const std::string &e_b64url);
	// AddRoleGrant: `cap_str` is a capability name string (see ParseCapability).
	// Unknown capability strings are silently dropped (fail-closed: under-grant is safe).
	// Object kind defaults to TABLE (back-compat).
	void AddRoleGrant(const std::string &role, const std::string &resource_ref, const std::string &cap_str);
	// Kind-aware grant push: same as AddRoleGrant but tags the grant with an ObjKind
	// (see ParseObjKind). Unknown cap OR kind string -> drop the grant (fail-closed).
	void AddRoleGrantKind(const std::string &role, const std::string &resource_ref, const std::string &cap_str,
	                      const std::string &kind_str);
	void AddGrantConstraint(const std::string &role, const std::string &table_ref,
	                        const std::vector<std::string> &columns,
	                        int32_t window_start_min, int32_t window_end_min);
	void SetLakeCatalog(const std::string &name);
	void AddUserRole(const std::string &user_id, const std::string &role);
	void AddServiceToken(const std::string &token, const std::string &user_id);
	bool LookupServiceToken(const std::string &token, std::string &user_id);

	// Non-catalog resource policy setters (additive into staging_; see PolicySnapshot).
	void AddSourcePolicy(const std::string &role, const std::string &pattern);
	void AddDestPolicy(const std::string &role, const std::string &pattern);
	void AddExtPolicy(const std::string &role, const std::string &pattern);
	void AddAttachPolicy(const std::string &role, const std::string &pattern);

	void Commit(); // promote staging -> live

	// ---- direct-to-live mutation (native GRANT/REVOKE authoring surface) ------
	// The ParserExtension GRANT/REVOKE statement (see birdshot_extension.cpp) mutates
	// the LIVE snapshot IMMEDIATELY — no staging/Commit round-trip — so a GRANT takes
	// effect on the very next authorize. These run ONLY from the table-function
	// execution of a trusted-path GRANT/REVOKE (the wire authorize path can never
	// reach them: it denies EXTENSION_STATEMENT / GRANT-shaped SQL fail-closed).
	//
	// cap_str / kind_str are re-validated fail-closed (ParseCapability / ParseObjKind):
	// an unknown string is a silent no-op (never over-grant). resource_ref is lowercased
	// to match the RefMatch invariant used by every other grant.
	//
	// KNOWN INTERACTION (spec §0, do NOT solve here): the gateway's applySnapshot does
	// reset->add->Commit on live_, which clobbers these direct-live grants. That is a
	// gateway reconcile concern; for standalone / tests direct-live is exactly right.
	void GrantLive(const std::string &role, const std::string &resource_ref, const std::string &cap_str,
	               const std::string &kind_str, bool grant_option = false, const std::string &grantor = "");
	// Column-list GRANT constraint (native `GRANT SELECT (c1,c2) ON t …`). Direct-to-live
	// mirror of AddGrantConstraint, but MERGES into the single column constraint for
	// (role, table_ref): a later column GRANT WIDENS the allow-list (PG-faithful) rather
	// than appending a second entry that would AND-narrow to the intersection. Window-only
	// constraints (empty columns) are left untouched — only the column dimension merges.
	// `columns` is lowercased by the caller. Enforced by EnforceBoundConstraints (columns
	// allow-list) exactly like a pushed constraint — no new enforcement path.
	void GrantConstraintLive(const std::string &role, const std::string &table_ref,
	                         const std::vector<std::string> &columns);
	// Inverse of GrantConstraintLive: drop every COLUMN constraint (non-empty columns) for
	// (role, table_ref). Window-only constraints are preserved. Paired with a base-cap
	// RevokeLive so REVOKE-with-columns removes both the grant AND the restriction (over-
	// revoke = under-grant = fail-safe; a lone constraint-drop would fail OPEN and is never
	// emitted).
	void RevokeConstraintLive(const std::string &role, const std::string &table_ref);
	// birdshot's FIRST grant-removal primitive: erases every live grant on `role` whose
	// (resource_ref, cap, kind) EXACTLY matches — the inverse of one GrantLive. Exact-ref
	// (not RefMatch) so a REVOKE undoes precisely the grant a prior GRANT added.
	void RevokeLive(const std::string &role, const std::string &resource_ref, const std::string &cap_str,
	                const std::string &kind_str);
	// Role membership (GRANT <role> TO <subject> / REVOKE <role> FROM <subject>).
	// GrantRoleLive is idempotent (dedups); also used to attach a subject's singleton
	// self-role so `TO <subject>` grants resolve through GrantsForUser.
	void GrantRoleLive(const std::string &subject, const std::string &role);
	void RevokeRoleLive(const std::string &subject, const std::string &role);

	// ---- pluggable grant store (spec §0) -------------------------------------
	// The in-memory State is always the hot read model for authorize; the store is
	// an optional durable backend (a `grants` table in an ATTACHed catalog). These
	// are runtime backend config and live OUTSIDE the swappable snapshot (ResetStaging
	// / Commit do not touch them). `kind` is "memory" (default, no persistence) or
	// "table" (write-through/load against `catalog`). Unknown kind -> stay memory
	// (fail-closed: never half-enable a store). Returns the effective kind.
	//
	// TODO(Stage B, spec §0): the transactional write-through + boot load against the
	// ATTACHed store catalog is NOT yet wired. It must run its SQL on a store-internal
	// connection (NOT a re-entrant query on the authorize/config ClientContext, which
	// can deadlock), inside a transaction, and update `live_` on commit. Enforcement
	// keeps reading the in-memory State (no per-query SQL on the hot path). The
	// instant-deny bridge (REVOKE also touching deny_user_) lands with Phase-3 wire
	// REVOKE. This pass implements: the config surface, the backend selector, and the
	// hard-DENY protection of the store catalog (IsProtectedRef / IsProtectedCatalog).
	std::string SetGrantStore(const std::string &kind, const std::string &target);
	std::string GrantStoreKind();
	std::string GrantStoreCatalog();
	// True iff `catalog` (lowercased) is the configured grant-store catalog. Used by
	// IsProtectedRef so no wire token can address the store catalog.
	bool IsProtectedCatalog(const std::string &catalog);

	// ---- sessions (authenticate writes, authorize reads) ---------------------
	void PutSession(const std::string &sid, Identity id);
	bool GetSession(const std::string &sid, Identity &out);

	// ---- revocation denylist -------------------------------------------------
	// expires_us == 0 means "never" (until explicitly lifted).
	void Revoke(const std::string &kind, const std::string &id, int64_t expires_us);
	void Unrevoke(const std::string &kind, const std::string &id);
	bool IsRevoked(const std::string &user_id, const std::string &jti, int64_t now_us);

	// ---- policy reads (authorize) -------------------------------------------
	// Returns a copy of the caller's merged grants (cheap: per-user grant sets
	// are small). Empty vector => no grants => default deny.
	std::vector<Grant> GrantsForUser(const std::string &user_id);
	// Merged constraints across the user's roles (same union semantics as
	// GrantsForUser; no dedup). Empty => no constraints.
	std::vector<GrantConstraint> ConstraintsForUser(const std::string &user_id);
	// Merged per-role resource policies for a user. Empty => deny (default-deny).
	std::vector<ResourcePolicy> SourcePoliciesForUser(const std::string &user_id);
	std::vector<ResourcePolicy> DestPoliciesForUser(const std::string &user_id);
	std::vector<ResourcePolicy> ExtPoliciesForUser(const std::string &user_id);
	std::vector<ResourcePolicy> AttachPoliciesForUser(const std::string &user_id);
	std::string LakeCatalog();
	AuthMode Mode();
	std::string Issuer();
	std::string Audience();
	std::string Secret();
	bool FindJwk(const std::string &kid, JwkKey &out);
	bool HasJwks();

	// ---- audit ring ----------------------------------------------------------
	void Log(AuditEntry entry);
	std::vector<AuditEntry> DrainAudit(size_t max_rows);

	// ---- status --------------------------------------------------------------
	std::string StatusSummary();

private:
	State() = default;

	std::mutex mtx_;
	PolicySnapshot live_;
	PolicySnapshot staging_;

	// Grant-store backend config (outside the swappable snapshot; spec §0).
	std::string store_kind_ = "memory"; // "memory" | "table"
	std::string store_target_;          // ATTACH target / DSN (table backend)
	std::string store_catalog_;         // protected catalog alias for the store

	std::unordered_map<std::string, Identity> sessions_;
	std::deque<std::string> session_order_; // insertion order for FIFO eviction
	std::unordered_map<std::string, int64_t> deny_user_; // user_id -> expires_us
	std::unordered_map<std::string, int64_t> deny_jti_;  // jti     -> expires_us

	std::deque<AuditEntry> audit_;
	static constexpr size_t kAuditCap = 10000;
};

} // namespace birdshot
