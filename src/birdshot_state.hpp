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
//   WRITE ⊇ READ (write grant satisfies a read need)
//   Every other pair is DISTINCT — no implicit cross-coverage.
enum class Capability : uint8_t {
	READ,        // SELECT (catalog table)
	WRITE,       // INSERT / UPDATE / DELETE  (write ⊇ read)
	CREATE,      // CREATE TABLE / VIEW / SCHEMA / INDEX / CTAS target
	DROP,        // DROP
	ALTER,       // ALTER (+ CREATE INDEX on a table)
	READ_SOURCE, // read_*/glob/COPY FROM source URI  — policy-gated, not RefMatch
	COPY_TO,     // COPY TO / EXPORT destination URI  — policy-gated
	ATTACH,      // ATTACH path/DSN                   — policy-gated
	DETACH,      // DETACH (catalog alias)
	INSTALL,     // INSTALL / LOAD extension name     — policy-gated
	PRAGMA_SET,  // SET / PRAGMA (deny-by-default allowlist)
};

// True iff a grant with capability `g` covers a need for capability `u`.
// Only WRITE ⊇ READ is implicit; every other capability must match exactly.
inline bool Covers(Capability g, Capability u) {
	if (g == u)
		return true;
	if (u == Capability::READ && g == Capability::WRITE)
		return true; // write grant also satisfies a read need
	return false;   // all other capabilities are mutually exclusive
}

// Parse a capability string produced by the policy compiler / host snapshot push.
// Returns true and sets `out` on a recognized name. Returns false (fail-closed,
// do NOT grant anything) on an unknown string — under-grant is the safe direction.
// Spellings: the legacy `"read"` / `"write"` action strings from the existing
// birdshot_add_role_grant() callers must round-trip unchanged.
inline bool ParseCapability(const std::string &s, Capability &out) {
	if (s == "read")        { out = Capability::READ;        return true; }
	if (s == "write")       { out = Capability::WRITE;       return true; }
	if (s == "create")      { out = Capability::CREATE;      return true; }
	if (s == "drop")        { out = Capability::DROP;        return true; }
	if (s == "alter")       { out = Capability::ALTER;       return true; }
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
	case Capability::CREATE:      return "create";
	case Capability::DROP:        return "drop";
	case Capability::ALTER:       return "alter";
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
};

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
	void AddRoleGrant(const std::string &role, const std::string &resource_ref, const std::string &cap_str);
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

	std::unordered_map<std::string, Identity> sessions_;
	std::deque<std::string> session_order_; // insertion order for FIFO eviction
	std::unordered_map<std::string, int64_t> deny_user_; // user_id -> expires_us
	std::unordered_map<std::string, int64_t> deny_jti_;  // jti     -> expires_us

	std::deque<AuditEntry> audit_;
	static constexpr size_t kAuditCap = 10000;
};

} // namespace birdshot
