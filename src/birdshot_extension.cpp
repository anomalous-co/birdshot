#define DUCKDB_EXTENSION_MAIN

#include "birdshot_extension.hpp"
#include "birdshot_state.hpp"
#include "birdshot_jwt.hpp"
#include "birdshot_acl.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"

#include <chrono>
#include <sstream>

namespace birdshot {

// ============================ State implementation ==========================

static int64_t NowUs() {
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

void State::ResetStaging() {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_ = PolicySnapshot();
}
void State::SetAuth(const std::string &issuer, const std::string &audience, AuthMode mode) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.issuer = issuer;
	staging_.audience = audience;
	staging_.mode = mode;
}
void State::SetSecret(const std::string &secret) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.secret = secret;
}
void State::AddJwk(const std::string &kid, const std::string &n, const std::string &e) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.jwks.push_back({kid, n, e});
}
void State::AddRoleGrant(const std::string &role, const std::string &table_ref, bool write) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.role_grants[role].push_back({LowerCopy(table_ref), write});
}
void State::AddUserRole(const std::string &user_id, const std::string &role) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.user_roles[user_id].push_back(role);
}
void State::AddServiceToken(const std::string &token, const std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.service_tokens[token] = user_id;
}
bool State::LookupServiceToken(const std::string &token, std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	// Constant-time over the secret bytes (a hash-map lookup + operator== on a
	// long-lived federation token is a remote timing oracle). Iterate all tokens,
	// compare with CRYPTO_memcmp, and don't early-return on match so the work is
	// independent of which (or whether a) token matched.
	bool found = false;
	for (const auto &kv : live_.service_tokens) {
		if (kv.first.size() == token.size() &&
		    CRYPTO_memcmp(kv.first.data(), token.data(), token.size()) == 0) {
			user_id = kv.second;
			found = true;
		}
	}
	return found;
}
void State::Commit() {
	std::lock_guard<std::mutex> lk(mtx_);
	live_ = staging_;
	staging_ = PolicySnapshot();
}

void State::PutSession(const std::string &sid, Identity id) {
	std::lock_guard<std::mutex> lk(mtx_);
	// birdshot can't observe quack disconnects, so the session map only grows.
	// Bound it with FIFO eviction of the OLDEST sessions (not a clear-all, which
	// a single peer could trigger in a reconnect loop to flush everyone else).
	if (sessions_.find(sid) == sessions_.end())
		session_order_.push_back(sid);
	sessions_[sid] = std::move(id);
	while (sessions_.size() > 50000 && !session_order_.empty()) {
		auto oldest = session_order_.front();
		session_order_.pop_front();
		sessions_.erase(oldest);
	}
}
bool State::GetSession(const std::string &sid, Identity &out) {
	std::lock_guard<std::mutex> lk(mtx_);
	auto it = sessions_.find(sid);
	if (it == sessions_.end())
		return false;
	out = it->second;
	return true;
}

void State::Revoke(const std::string &kind, const std::string &id, int64_t expires_us) {
	std::lock_guard<std::mutex> lk(mtx_);
	if (kind == "user")
		deny_user_[id] = expires_us;
	else if (kind == "jti")
		deny_jti_[id] = expires_us;
}
void State::Unrevoke(const std::string &kind, const std::string &id) {
	std::lock_guard<std::mutex> lk(mtx_);
	if (kind == "user")
		deny_user_.erase(id);
	else if (kind == "jti")
		deny_jti_.erase(id);
}
static bool ActiveRevocation(const std::unordered_map<std::string, int64_t> &m, const std::string &id, int64_t now_us) {
	auto it = m.find(id);
	if (it == m.end())
		return false;
	return it->second == 0 || now_us <= it->second; // 0 == never expires
}
bool State::IsRevoked(const std::string &user_id, const std::string &jti, int64_t now_us) {
	std::lock_guard<std::mutex> lk(mtx_);
	return ActiveRevocation(deny_user_, user_id, now_us) || (!jti.empty() && ActiveRevocation(deny_jti_, jti, now_us));
}

std::vector<Grant> State::GrantsForUser(const std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	std::vector<Grant> out;
	auto it = live_.user_roles.find(user_id);
	if (it == live_.user_roles.end())
		return out;
	for (const auto &role : it->second) {
		auto git = live_.role_grants.find(role);
		if (git != live_.role_grants.end())
			out.insert(out.end(), git->second.begin(), git->second.end());
	}
	return out;
}
AuthMode State::Mode() {
	std::lock_guard<std::mutex> lk(mtx_);
	return live_.mode;
}
std::string State::Issuer() {
	std::lock_guard<std::mutex> lk(mtx_);
	return live_.issuer;
}
std::string State::Audience() {
	std::lock_guard<std::mutex> lk(mtx_);
	return live_.audience;
}
std::string State::Secret() {
	std::lock_guard<std::mutex> lk(mtx_);
	return live_.secret;
}
bool State::FindJwk(const std::string &kid, JwkKey &out) {
	std::lock_guard<std::mutex> lk(mtx_);
	for (const auto &k : live_.jwks) {
		if (kid.empty() || k.kid == kid) {
			out = k;
			return true;
		}
	}
	return false;
}
bool State::HasJwks() {
	std::lock_guard<std::mutex> lk(mtx_);
	return !live_.jwks.empty();
}

void State::Log(AuditEntry entry) {
	std::lock_guard<std::mutex> lk(mtx_);
	audit_.push_back(std::move(entry));
	while (audit_.size() > kAuditCap)
		audit_.pop_front();
}
std::vector<AuditEntry> State::DrainAudit(size_t max_rows) {
	std::lock_guard<std::mutex> lk(mtx_);
	std::vector<AuditEntry> out;
	size_t n = std::min(max_rows, audit_.size());
	for (size_t i = 0; i < n; i++) {
		out.push_back(std::move(audit_.front()));
		audit_.pop_front();
	}
	return out;
}
std::string State::StatusSummary() {
	std::lock_guard<std::mutex> lk(mtx_);
	std::ostringstream os;
	const char *m = live_.mode == AuthMode::DEV ? "dev" : live_.mode == AuthMode::HS256 ? "hs256" : "rs256";
	os << "mode=" << m << " issuer=" << live_.issuer << " roles=" << live_.role_grants.size()
	   << " users=" << live_.user_roles.size() << " jwks=" << live_.jwks.size() << " sessions=" << sessions_.size()
	   << " deny_user=" << deny_user_.size() << " deny_jti=" << deny_jti_.size() << " audit=" << audit_.size();
	return os.str();
}

// ============================ grant matching ================================

static bool RefMatch(const std::string &grant_ref, const std::string &use_ref) {
	if (grant_ref == "*")
		return true;
	if (grant_ref.size() >= 2 && grant_ref.compare(grant_ref.size() - 2, 2, ".*") == 0) {
		std::string prefix = grant_ref.substr(0, grant_ref.size() - 1); // keep trailing '.'
		return use_ref.rfind(prefix, 0) == 0;
	}
	if (grant_ref == use_ref)
		return true;
	// suffix match in either direction (handles differing qualification)
	if (grant_ref.size() > use_ref.size() &&
	    grant_ref.compare(grant_ref.size() - use_ref.size() - 1, use_ref.size() + 1, "." + use_ref) == 0)
		return true;
	if (use_ref.size() > grant_ref.size() &&
	    use_ref.compare(use_ref.size() - grant_ref.size() - 1, grant_ref.size() + 1, "." + grant_ref) == 0)
		return true;
	return false;
}

// A table use is satisfied if some grant matches the ref AND covers the action.
// A 'write' grant also satisfies a 'read' use (write ⊇ read).
static bool UseSatisfied(const TableUse &use, const std::vector<Grant> &grants) {
	for (const auto &g : grants) {
		if (!RefMatch(g.table_ref, use.ref))
			continue;
		if (use.write) {
			if (g.write)
				return true;
		} else {
			return true; // any matching grant (read or write) covers a read
		}
	}
	return false;
}

} // namespace birdshot

namespace duckdb {

using namespace birdshot;

// ============================ arg / result helpers ==========================

static std::string ArgStr(Vector &v, idx_t i) {
	return FlatVector::GetData<string_t>(v)[i].GetString();
}
static bool ArgNull(Vector &v, idx_t i) {
	return !FlatVector::Validity(v).RowIsValid(i);
}
static void SetStrResult(Vector &result, idx_t i, const std::string &s) {
	FlatVector::GetData<string_t>(result)[i] = StringVector::AddString(result, s);
}

// ============================ auth / authz hooks ============================

// birdshot_authenticate(sid, token, server_token) -> BOOLEAN
static void Authenticate(DataChunk &args, ExpressionState &state, Vector &result) {
	args.data[0].Flatten(args.size());
	args.data[1].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	auto res = FlatVector::GetData<bool>(result);
	auto &st = State::Get();
	int64_t now = NowUs();
	for (idx_t i = 0; i < args.size(); i++) {
		std::string sid = ArgNull(args.data[0], i) ? "" : ArgStr(args.data[0], i);
		std::string token = ArgNull(args.data[1], i) ? "" : ArgStr(args.data[1], i);
		AuditEntry e;
		e.ts_us = now;
		e.event = "authenticate";
		e.sid = sid;

		// 1. Static service token (machine/peer auth) — checked before JWT so the
		//    quack federation token keeps working after birdshot takes over auth.
		std::string svc_user;
		if (st.LookupServiceToken(token, svc_user)) {
			st.PutSession(sid, Identity {svc_user, "", 0});
			e.user_id = svc_user;
			e.decision = "allow";
			e.reason = "service_token";
			res[i] = true;
			st.Log(std::move(e));
			continue;
		}

		// 2. User JWT.
		Claims c = VerifyJwt(token, st, now);
		if (c.ok) {
			st.PutSession(sid, Identity {c.sub, c.jti, c.exp_us});
			e.user_id = c.sub;
			e.decision = "allow";
			e.reason = "ok";
			res[i] = true;
		} else {
			e.decision = "deny";
			e.reason = c.error.empty() ? "bad_token" : c.error;
			res[i] = false;
		}
		st.Log(std::move(e));
	}
}

// birdshot_authorize(sid, query) -> BOOLEAN
static void Authorize(DataChunk &args, ExpressionState &state, Vector &result) {
	args.data[0].Flatten(args.size());
	args.data[1].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	auto res = FlatVector::GetData<bool>(result);
	auto &st = State::Get();
	int64_t now = NowUs();
	for (idx_t i = 0; i < args.size(); i++) {
		std::string sid = ArgNull(args.data[0], i) ? "" : ArgStr(args.data[0], i);
		std::string query = ArgNull(args.data[1], i) ? "" : ArgStr(args.data[1], i);

		AuditEntry e;
		e.ts_us = now;
		e.event = "authorize";
		e.sid = sid;
		e.query = query;
		bool allow = false;
		std::string reason;

		Identity id;
		if (!st.GetSession(sid, id)) {
			reason = "no_session";
		} else if (id.exp_us != 0 && now > id.exp_us) {
			reason = "expired";
		} else if (st.IsRevoked(id.user_id, id.jti, now)) {
			reason = "revoked";
		} else {
			e.user_id = id.user_id;
			AclAnalysis a = Analyze(query);
			if (a.cls == AclClass::ALLOW_ALL) {
				allow = true;
				reason = "ok";
			} else if (a.cls == AclClass::FORBIDDEN) {
				reason = a.reason;
			} else if (a.cls == AclClass::PARSE_ERR) {
				reason = a.reason; // fail closed
			} else {
				// CHECK: every touched table must be covered by a grant.
				auto grants = st.GrantsForUser(id.user_id);
				bool all_ok = true;
				for (const auto &use : a.tables) {
					if (!UseSatisfied(use, grants)) {
						all_ok = false;
						reason = std::string("acl:") + (use.write ? "w:" : "r:") + use.ref;
						break;
					}
				}
				allow = all_ok;
				if (allow)
					reason = "ok";
			}
		}
		e.user_id = id.user_id;
		e.decision = allow ? "allow" : "deny";
		e.reason = reason;
		st.Log(std::move(e));
		res[i] = allow;
	}
}

// ============================ config setters ================================

static AuthMode ParseMode(const std::string &m) {
	if (m == "rs256")
		return AuthMode::RS256;
	if (m == "hs256")
		return AuthMode::HS256;
	return AuthMode::DEV;
}

static void ResetConfig(DataChunk &args, ExpressionState &state, Vector &result) {
	State::Get().ResetStaging();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++)
		SetStrResult(result, i, "ok");
}
static void SetAuthFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 3; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().SetAuth(ArgStr(args.data[0], i), ArgStr(args.data[1], i), ParseMode(ArgStr(args.data[2], i)));
		SetStrResult(result, i, "ok");
	}
}
static void SetSecretFn(DataChunk &args, ExpressionState &state, Vector &result) {
	args.data[0].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().SetSecret(ArgStr(args.data[0], i));
		SetStrResult(result, i, "ok");
	}
}
static void AddJwkFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 3; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().AddJwk(ArgStr(args.data[0], i), ArgStr(args.data[1], i), ArgStr(args.data[2], i));
		SetStrResult(result, i, "ok");
	}
}
static void AddRoleGrantFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 3; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		std::string action = ArgStr(args.data[2], i);
		State::Get().AddRoleGrant(ArgStr(args.data[0], i), ArgStr(args.data[1], i), action == "write");
		SetStrResult(result, i, "ok");
	}
}
static void AddUserRoleFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 2; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().AddUserRole(ArgStr(args.data[0], i), ArgStr(args.data[1], i));
		SetStrResult(result, i, "ok");
	}
}
static void AddServiceTokenFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 2; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().AddServiceToken(ArgStr(args.data[0], i), ArgStr(args.data[1], i));
		SetStrResult(result, i, "ok");
	}
}
static void CommitConfigFn(DataChunk &args, ExpressionState &state, Vector &result) {
	State::Get().Commit();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++)
		SetStrResult(result, i, "ok");
}

// ============================ revocation ====================================

// birdshot_revoke(kind, id, reason, expires_us) -> VARCHAR
static void RevokeFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 4; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		int64_t exp = ArgNull(args.data[3], i) ? 0 : FlatVector::GetData<int64_t>(args.data[3])[i];
		State::Get().Revoke(ArgStr(args.data[0], i), ArgStr(args.data[1], i), exp);
		SetStrResult(result, i, "ok");
	}
}
static void UnrevokeFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 2; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().Unrevoke(ArgStr(args.data[0], i), ArgStr(args.data[1], i));
		SetStrResult(result, i, "ok");
	}
}

// ============================ audit drain / status ==========================

// birdshot_log_drain(max_rows) -> VARCHAR (newline-delimited records; free-text
// fields base64url-encoded so the host never has to unescape delimiters).
static void LogDrainFn(DataChunk &args, ExpressionState &state, Vector &result) {
	args.data[0].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		int64_t max_rows = ArgNull(args.data[0], i) ? 1000 : FlatVector::GetData<int64_t>(args.data[0])[i];
		auto rows = State::Get().DrainAudit(static_cast<size_t>(max_rows < 0 ? 0 : max_rows));
		std::ostringstream os;
		for (const auto &r : rows) {
			// sid and user_id are b64url-encoded too: user_id is the JWT `sub`
			// (issuer/attacker-influenced) and could carry tab/newline to forge
			// audit rows. event/decision are fixed internal strings, left raw.
			os << r.ts_us << '\t' << r.event << '\t' << B64UrlEncode(r.sid) << '\t' << B64UrlEncode(r.user_id) << '\t'
			   << r.decision << '\t' << B64UrlEncode(r.reason) << '\t' << B64UrlEncode(r.query) << '\n';
		}
		SetStrResult(result, i, os.str());
	}
}
static void StatusFn(DataChunk &args, ExpressionState &state, Vector &result) {
	std::string s = State::Get().StatusSummary();
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++)
		SetStrResult(result, i, s);
}

// ============================ registration ==================================

static void Register(ExtensionLoader &loader, const std::string &name, const vector<LogicalType> &args,
                     const LogicalType &ret, scalar_function_t fn) {
	ScalarFunction sf(name, args, ret, fn);
	sf.stability = FunctionStability::VOLATILE; // never fold/cache: these have side effects
	sf.null_handling = FunctionNullHandling::SPECIAL_HANDLING;
	loader.RegisterFunction(sf);
}

static void LoadInternal(ExtensionLoader &loader) {
	const auto V = LogicalType::VARCHAR;
	const auto B = LogicalType::BOOLEAN;
	const auto I = LogicalType::BIGINT;

	// Quack hooks.
	Register(loader, "birdshot_authenticate", {V, V, V}, B, Authenticate);
	Register(loader, "birdshot_authorize", {V, V}, B, Authorize);

	// Config staging / promotion (host loader push path).
	Register(loader, "birdshot_reset_config", {}, V, ResetConfig);
	Register(loader, "birdshot_set_auth", {V, V, V}, V, SetAuthFn);
	Register(loader, "birdshot_set_secret", {V}, V, SetSecretFn);
	Register(loader, "birdshot_add_jwk", {V, V, V}, V, AddJwkFn);
	Register(loader, "birdshot_add_role_grant", {V, V, V}, V, AddRoleGrantFn);
	Register(loader, "birdshot_add_user_role", {V, V}, V, AddUserRoleFn);
	Register(loader, "birdshot_add_service_token", {V, V}, V, AddServiceTokenFn);
	Register(loader, "birdshot_commit_config", {}, V, CommitConfigFn);

	// Revocation (instant in-memory denylist).
	Register(loader, "birdshot_revoke", {V, V, V, I}, V, RevokeFn);
	Register(loader, "birdshot_unrevoke", {V, V}, V, UnrevokeFn);

	// Audit + status.
	Register(loader, "birdshot_log_drain", {I}, V, LogDrainFn);
	Register(loader, "birdshot_status", {}, V, StatusFn);
}

void BirdshotExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string BirdshotExtension::Name() {
	return "birdshot";
}
std::string BirdshotExtension::Version() const {
#ifdef EXT_VERSION_BIRDSHOT
	return EXT_VERSION_BIRDSHOT;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(birdshot, loader) {
	duckdb::LoadInternal(loader);
}
}
