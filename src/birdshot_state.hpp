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

// A single (table, action) permission attached to a role. `write` false == read.
struct Grant {
	std::string table_ref; // normalized "catalog.schema.table"; last segment may be "*"
	bool write;
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
	// Static, long-lived credentials for machine/peer auth (e.g. the quack
	// federation token), checked before JWT verification. token -> user_id.
	std::unordered_map<std::string, std::string> service_tokens;
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
	void AddRoleGrant(const std::string &role, const std::string &table_ref, bool write);
	void AddUserRole(const std::string &user_id, const std::string &role);
	void AddServiceToken(const std::string &token, const std::string &user_id);
	bool LookupServiceToken(const std::string &token, std::string &user_id);
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
