#define DUCKDB_EXTENSION_MAIN

#include "birdshot_extension.hpp"
#include "birdshot_state.hpp"
#include "birdshot_jwt.hpp"
#include "birdshot_acl.hpp"          // parse-walk fallback (kept compiled in-tree)
#include "birdshot_bind_analyze.hpp" // bind-and-walk primary path

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/vector_operations/vector_operations.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/parser/parser_extension.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/parser/column_list.hpp"
#include "duckdb/common/enums/on_entry_not_found.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <sstream>

namespace birdshot {

// ============================ State implementation ==========================

static int64_t NowUs() {
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

// Current UTC minutes-of-day [0,1439] for time-window enforcement. Uses gmtime
// (UTC) — constraint windows are specified in UTC.
static int32_t NowMinutesUtc() {
	std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	std::tm out;
#if defined(_WIN32)
	gmtime_s(&out, &t);
#else
	gmtime_r(&t, &out);
#endif
	return static_cast<int32_t>(out.tm_hour * 60 + out.tm_min);
}

// Inside a (possibly wrapping) [start,end] minute window, inclusive. Caller
// guarantees start >= 0 (a window is configured).
static bool WithinWindow(int32_t now, int32_t start, int32_t end) {
	if (end < 0)
		end = start; // half-configured window: treat as a single-minute window
	if (start <= end)
		return now >= start && now <= end;
	return now >= start || now <= end; // wraps past midnight
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
void State::AddRoleGrant(const std::string &role, const std::string &resource_ref, const std::string &cap_str) {
	Capability cap;
	if (!ParseCapability(cap_str, cap))
		return; // unknown capability string — fail-closed: drop the grant, don't over-grant
	std::lock_guard<std::mutex> lk(mtx_);
	// Explicit field assignment (not brace-init): under the forced -std=c++11, Grant's
	// in-class default initializer (cap = READ) makes it a non-aggregate, so {..} fails.
	Grant g;
	g.resource_ref = LowerCopy(resource_ref);
	g.cap = cap;
	g.kind = ObjKind::TABLE; // legacy path: default kind
	staging_.role_grants[role].push_back(g);
}
void State::AddRoleGrantKind(const std::string &role, const std::string &resource_ref, const std::string &cap_str,
                             const std::string &kind_str) {
	Capability cap;
	if (!ParseCapability(cap_str, cap))
		return; // unknown capability -> fail-closed (drop, don't over-grant)
	ObjKind kind;
	if (!ParseObjKind(kind_str, kind))
		return; // unknown object kind -> fail-closed (drop)
	std::lock_guard<std::mutex> lk(mtx_);
	Grant g;
	g.resource_ref = LowerCopy(resource_ref);
	g.cap = cap;
	g.kind = kind;
	staging_.role_grants[role].push_back(g);
}
std::string State::SetGrantStore(const std::string &kind, const std::string &target) {
	std::lock_guard<std::mutex> lk(mtx_);
	if (kind == "table") {
		store_kind_ = "table";
		store_target_ = target;
		// The store lives in a protected catalog. We use a fixed reserved alias so no
		// wire token can address it (IsProtectedRef covers `__birdshot`), independent
		// of whatever the ATTACH target string is.
		store_catalog_ = "__birdshot";
		return store_kind_;
	}
	// Unknown / "memory" -> memory backend (fail-closed: never half-enable a store).
	store_kind_ = "memory";
	store_target_.clear();
	store_catalog_.clear();
	return store_kind_;
}
std::string State::GrantStoreKind() {
	std::lock_guard<std::mutex> lk(mtx_);
	return store_kind_;
}
std::string State::GrantStoreCatalog() {
	std::lock_guard<std::mutex> lk(mtx_);
	return store_catalog_;
}
bool State::IsProtectedCatalog(const std::string &catalog) {
	std::lock_guard<std::mutex> lk(mtx_);
	return !store_catalog_.empty() && catalog == store_catalog_;
}
void State::AddSourcePolicy(const std::string &role, const std::string &pattern) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.source_policies[role].push_back({pattern});
}
void State::AddDestPolicy(const std::string &role, const std::string &pattern) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.dest_policies[role].push_back({pattern});
}
void State::AddExtPolicy(const std::string &role, const std::string &pattern) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.ext_policies[role].push_back({pattern});
}
void State::AddAttachPolicy(const std::string &role, const std::string &pattern) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.attach_policies[role].push_back({pattern});
}

void State::AddGrantConstraint(const std::string &role, const std::string &table_ref,
                               const std::vector<std::string> &columns,
                               int32_t window_start_min, int32_t window_end_min) {
	std::lock_guard<std::mutex> lk(mtx_);
	GrantConstraint c;
	c.table_ref = LowerCopy(table_ref); // mirror AddRoleGrant's lowercasing invariant
	c.columns = columns;                // already lowercased by the setter fn
	c.window_start_min = window_start_min;
	c.window_end_min = window_end_min;
	staging_.role_constraints[role].push_back(c);
}
void State::SetLakeCatalog(const std::string &name) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.lake_catalog = name;
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

// ---- direct-to-live mutation (native GRANT/REVOKE) -------------------------
// These write live_ directly (no staging) so a GRANT takes effect on the next
// authorize. Reachable ONLY from the trusted-path GRANT/REVOKE table function.
void State::GrantLive(const std::string &role, const std::string &resource_ref, const std::string &cap_str,
                      const std::string &kind_str) {
	Capability cap;
	if (!ParseCapability(cap_str, cap))
		return; // unknown capability -> fail-closed no-op (never over-grant)
	ObjKind kind;
	if (!ParseObjKind(kind_str, kind))
		return; // unknown object kind -> fail-closed no-op
	std::lock_guard<std::mutex> lk(mtx_);
	Grant g;
	g.resource_ref = LowerCopy(resource_ref);
	g.cap = cap;
	g.kind = kind;
	live_.role_grants[role].push_back(g);
}
void State::RevokeLive(const std::string &role, const std::string &resource_ref, const std::string &cap_str,
                       const std::string &kind_str) {
	Capability cap;
	if (!ParseCapability(cap_str, cap))
		return; // unknown capability -> nothing could match; safe no-op
	ObjKind kind;
	if (!ParseObjKind(kind_str, kind))
		return;
	std::string ref = LowerCopy(resource_ref);
	std::lock_guard<std::mutex> lk(mtx_);
	auto it = live_.role_grants.find(role);
	if (it == live_.role_grants.end())
		return;
	auto &v = it->second;
	// Erase every grant whose (ref, cap, kind) exactly matches — the inverse of GrantLive.
	v.erase(std::remove_if(v.begin(), v.end(),
	                       [&](const Grant &g) {
		                       return g.resource_ref == ref && g.cap == cap && g.kind == kind;
	                       }),
	        v.end());
}
void State::GrantRoleLive(const std::string &subject, const std::string &role) {
	std::lock_guard<std::mutex> lk(mtx_);
	auto &roles = live_.user_roles[subject];
	for (const auto &r : roles)
		if (r == role)
			return; // idempotent: already a member
	roles.push_back(role);
}
void State::RevokeRoleLive(const std::string &subject, const std::string &role) {
	std::lock_guard<std::mutex> lk(mtx_);
	auto it = live_.user_roles.find(subject);
	if (it == live_.user_roles.end())
		return;
	auto &v = it->second;
	v.erase(std::remove(v.begin(), v.end(), role), v.end());
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
std::vector<GrantConstraint> State::ConstraintsForUser(const std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	std::vector<GrantConstraint> out;
	auto it = live_.user_roles.find(user_id);
	if (it == live_.user_roles.end())
		return out;
	for (const auto &role : it->second) {
		auto cit = live_.role_constraints.find(role);
		if (cit != live_.role_constraints.end())
			out.insert(out.end(), cit->second.begin(), cit->second.end());
	}
	return out;
}
// Shared logic: collect all ResourcePolicy entries for a user across their roles,
// reading from the given policy store (passed as a reference to avoid pointer-to-
// member qualification complexity). Caller holds mtx_ and passes live_.
static std::vector<ResourcePolicy>
MergeResourcePoliciesImpl(const PolicySnapshot &snap, const std::string &user_id,
                          const std::unordered_map<std::string, std::vector<ResourcePolicy>> &store) {
	std::vector<ResourcePolicy> out;
	auto it = snap.user_roles.find(user_id);
	if (it == snap.user_roles.end())
		return out;
	for (const auto &role : it->second) {
		auto pit = store.find(role);
		if (pit != store.end())
			out.insert(out.end(), pit->second.begin(), pit->second.end());
	}
	return out;
}

std::vector<ResourcePolicy> State::SourcePoliciesForUser(const std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	return MergeResourcePoliciesImpl(live_, user_id, live_.source_policies);
}
std::vector<ResourcePolicy> State::DestPoliciesForUser(const std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	return MergeResourcePoliciesImpl(live_, user_id, live_.dest_policies);
}
std::vector<ResourcePolicy> State::ExtPoliciesForUser(const std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	return MergeResourcePoliciesImpl(live_, user_id, live_.ext_policies);
}
std::vector<ResourcePolicy> State::AttachPoliciesForUser(const std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	return MergeResourcePoliciesImpl(live_, user_id, live_.attach_policies);
}

std::string State::LakeCatalog() {
	std::lock_guard<std::mutex> lk(mtx_);
	return live_.lake_catalog;
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
	size_t constraints = 0;
	for (const auto &kv : live_.role_constraints)
		constraints += kv.second.size();
	os << "mode=" << m << " issuer=" << live_.issuer << " roles=" << live_.role_grants.size()
	   << " users=" << live_.user_roles.size() << " jwks=" << live_.jwks.size() << " sessions=" << sessions_.size()
	   << " deny_user=" << deny_user_.size() << " deny_jti=" << deny_jti_.size() << " audit=" << audit_.size()
	   << " constraints=" << constraints;
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

// A table use is satisfied if some grant matches the ref AND its capability covers
// the use's required capability (via Covers()). WRITE ⊇ READ: a write grant also
// satisfies a read need. All other capability pairs are distinct.
static bool UseSatisfied(const TableUse &use, const std::vector<Grant> &grants) {
	for (const auto &g : grants) {
		if (!RefMatch(g.resource_ref, use.ref))
			continue;
		if (!KindMatch(g.kind, use.kind))
			continue; // object-kind gate (spec §1c): a table grant never covers a sequence use
		if (Covers(g.cap, use.cap))
			return true;
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

// Resolve a base table's full (lowercased) column-name list against the lake
// catalog. Returns false (fail-closed) on missing context or unknown
// catalog/schema/table. `lake_catalog` may be empty, in which case the ref's own
// catalog (or DuckDB's default search path) is used. The result is the catalog
// column SET C(use), reused for both positional resolution (#N -> names[N-1]) and
// S8 unqualified-name membership tests.
static bool ResolveTableColumns(ExpressionState &state, const std::string &lake_catalog, const TableUse &use,
                                std::vector<std::string> &out_names) {
	if (!state.HasContext())
		return false;
	std::string catalog = !use.catalog.empty() ? use.catalog : lake_catalog;
	std::string schema = !use.schema.empty() ? use.schema : "main";
	try {
		ClientContext &ctx = state.GetContext();
		auto entry = Catalog::GetEntry<TableCatalogEntry>(ctx, catalog, schema, use.table,
		                                                  OnEntryNotFound::RETURN_NULL);
		if (!entry)
			return false;
		const ColumnList &cols = entry->GetColumns();
		vector<std::string> names = cols.GetColumnNames();
		out_names.clear();
		out_names.reserve(names.size());
		for (auto &n : names)
			out_names.push_back(LowerCopy(n));
		return true;
	} catch (...) {
		return false; // unknown catalog/schema, etc. -> deny
	}
}

// Enforce column allow-lists + time windows for the touched tables. Returns true
// iff every constraint is satisfied; sets `reason` (col:<ref> / window:<ref>) on
// the first deny. Fails closed on any ambiguity or unresolved column.
static bool EnforceConstraints(const AclAnalysis &a, const std::vector<GrantConstraint> &constraints,
                               const std::string &lake_catalog, ExpressionState &state, std::string &reason) {
	if (constraints.empty())
		return true;

	int n_tables = static_cast<int>(a.tables.size());
	int32_t now_min = -1; // computed lazily, once

	for (const auto &use : a.tables) {
		for (const auto &c : constraints) {
			if (!RefMatch(c.table_ref, use.ref))
				continue;

			// ---- time window (clock-based; independent of query form) ----------
			if (c.window_start_min >= 0) {
				if (now_min < 0)
					now_min = NowMinutesUtc();
				if (!WithinWindow(now_min, c.window_start_min, c.window_end_min)) {
					reason = std::string("window:") + use.ref;
					return false;
				}
			}

			// ---- column allow-list ---------------------------------------------
			if (c.columns.empty())
				continue; // unrestricted columns

			std::unordered_map<std::string, bool> allowed;
			for (const auto &col : c.columns)
				allowed[col] = true;

			// A non-fully-enumerated star can't be checked against the allow-list.
			// Deny only the table this star could actually read: a bare star (empty
			// qualifier) denies every constrained table; a `t.*` denies only the
			// table aliased `t`. A star qualified to a DIFFERENT table is harmless.
			for (const auto &sq : a.star_quals) {
				if (sq.empty() || sq == use.alias) {
					reason = std::string("col:") + use.ref;
					return false;
				}
			}

			// Catalog column set C(use), resolved lazily on first need and cached, so
			// a fully-qualified statement that needs no resolution never depends on
			// catalog availability. resolved: 0=not yet, 1=ok, -1=lookup failed.
			std::vector<std::string> use_cols;
			int resolved = 0;
			auto ensure_cols = [&]() -> bool {
				if (resolved == 0)
					resolved = ResolveTableColumns(state, lake_catalog, use, use_cols) ? 1 : -1;
				return resolved == 1;
			};

			if (n_tables == 1) {
				// Single base table: every collected column/position is charged here.
				for (const auto &col : a.columns) {
					if (allowed.find(col.name) == allowed.end()) {
						reason = std::string("col:") + use.ref;
						return false;
					}
				}
				for (int64_t pos : a.positions) {
					if (!ensure_cols()) {
						reason = std::string("col:") + use.ref;
						return false;
					}
					size_t idx = pos < 1 ? use_cols.size() : static_cast<size_t>(pos - 1);
					if (idx >= use_cols.size() || allowed.find(use_cols[idx]) == allowed.end()) {
						reason = std::string("col:") + use.ref;
						return false;
					}
				}
			} else {
				// Multiple base tables. A select-list positional ref is ambiguous /
				// exotic in a multi-table statement (form-A pushdown is single-table
				// only) -> fail closed. (Residual: an ORDER BY 1 / GROUP BY 1 output-
				// ordinal also denies here; agents use the named form.)
				if (!a.positions.empty()) {
					reason = std::string("col:") + use.ref;
					return false;
				}
				for (const auto &col : a.columns) {
					if (!col.qualifier.empty()) {
						// Qualified: GetTableName() returns the TABLE component even for
						// a schema-qualified `main.t.c3` (so it matches use.alias).
						if (col.qualifier != use.alias)
							continue; // charged to a different table
						if (allowed.find(col.name) == allowed.end()) {
							reason = std::string("col:") + use.ref;
							return false;
						}
						continue;
					}
					// Unqualified (S8): the name could read ANY touched table that has a
					// column by this name. If it IS one of this constrained table's
					// columns and is NOT allowed -> deny. If it's not this table's column
					// (alias / computed output / another table's column) -> skip for use.
					if (!ensure_cols()) {
						reason = std::string("col:") + use.ref;
						return false;
					}
					bool in_table = false;
					for (const auto &cn : use_cols)
						if (cn == col.name) {
							in_table = true;
							break;
						}
					if (in_table && allowed.find(col.name) == allowed.end()) {
						reason = std::string("col:") + use.ref;
						return false;
					}
				}
			}
		}
	}
	return true;
}

// ---- bind-and-walk enforcement (primary path) ------------------------------

// Grant check for a bound table use. A BoundTableUse carries a SET of required caps
// (spec §1d): EVERY cap must be covered by some grant (ref + kind + capability). If
// `missing` is non-null it receives the FIRST uncovered cap (for the deny reason).
// Fails closed on an empty cap set (a real use always has >=1 cap).
static bool BoundUseSatisfied(const BoundTableUse &use, const std::vector<Grant> &grants,
                              Capability *missing = nullptr) {
	if (use.caps.empty()) {
		if (missing)
			*missing = Capability::READ;
		return false; // fail closed: a touched table with no required cap is anomalous
	}
	for (Capability need : use.caps) {
		bool covered = false;
		for (const auto &g : grants) {
			if (!RefMatch(g.resource_ref, use.ref))
				continue;
			if (!KindMatch(g.kind, use.kind))
				continue;
			if (Covers(g.cap, need)) {
				covered = true;
				break;
			}
		}
		if (!covered) {
			if (missing)
				*missing = need;
			return false;
		}
	}
	return true;
}

// Column allow-list + time-window enforcement over the bound analysis. Every
// column the binder resolved is a REAL catalog column attributed to its REAL
// table (by table_index), so there is no single/multi-table split, no positional
// resolution, no star handling — just set membership. Fails closed on any
// non-allowed column. Returns true iff every constraint is satisfied.
static bool EnforceBoundConstraints(const BoundAclAnalysis &a, const std::vector<GrantConstraint> &constraints,
                                    std::string &reason) {
	if (constraints.empty())
		return true;
	int32_t now_min = -1; // computed lazily, once
	for (const auto &use : a.tables) {
		for (const auto &c : constraints) {
			if (!RefMatch(c.table_ref, use.ref))
				continue;

			// time window (clock-based; independent of query form).
			if (c.window_start_min >= 0) {
				if (now_min < 0)
					now_min = NowMinutesUtc();
				if (!WithinWindow(now_min, c.window_start_min, c.window_end_min)) {
					reason = std::string("window:") + use.ref;
					return false;
				}
			}

			// column allow-list: every resolved read column must be allowed.
			if (c.columns.empty())
				continue; // unrestricted
			std::unordered_map<std::string, bool> allowed;
			for (const auto &col : c.columns)
				allowed[col] = true;
			for (const auto &col : use.read_cols) {
				if (allowed.find(col) == allowed.end()) {
					reason = std::string("col:") + use.ref;
					return false;
				}
			}
		}
	}
	return true;
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
			// Two-layer analysis:
			//   (1) PARSE-WALK PRE-FILTER (forbidden-class gate): the parse-walk's
			//       statement-type allowlist + dangerous-function / autoload-cast /
			//       non-introspection-table-function denylist. Bind-and-walk extracts
			//       tables/columns but does NOT subsume class gating — a forbidden
			//       statement (ATTACH/PRAGMA/DROP), a birdshot_* / read_* call, or a
			//       non-introspection table function binds to NO base-table GET and
			//       would otherwise fall through to ALLOW_ALL. So the parse-walk's
			//       forbidden verdict is a mandatory pre-filter; we consume ONLY its
			//       class (its table/column extraction is superseded by bind-walk).
			//   (2) BIND-AND-WALK EXTRACTION: bind against the lake catalog (no
			//       optimizer) and walk the bound plan for fully-resolved
			//       tables/columns (structs/stars/positionals/CTEs/multi-table all
			//       resolved by the binder).
			AclAnalysis pre = Analyze(query);
			if (pre.cls == AclClass::FORBIDDEN || pre.cls == AclClass::PARSE_ERR) {
				reason = pre.reason; // fail closed on forbidden class / unparseable
			} else if (!pre.cap_uses.empty() || !pre.policy_uses.empty()) {
				// ── PARSE-AUTHORIZED PATH (full-scope capability classes) ───
				// The batch contains a CREATE/DROP/ALTER/DETACH/COPY/ATTACH/INSTALL/LOAD
				// statement. These are authorized ENTIRELY here from the parse tree — the
				// bind-walk is for SELECT/DML only (its unknown-operator floor is default-
				// ALLOW, and external resources can't bind under enable_external_access=
				// false). Every catalog target is checked against grants (capability-aware
				// Covers); every external resource against the role's policy allowlist.
				auto grants = st.GrantsForUser(id.user_id);
				bool all_ok = true;
				// (a) catalog DDL targets (CREATE/DROP/ALTER/DETACH + COPY-FROM write target).
				for (const auto &use : pre.cap_uses) {
					if (!UseSatisfied(use, grants)) {
						all_ok = false;
						reason = std::string("acl:") + CapabilityName(use.cap) + ":" + use.ref;
						break;
					}
				}
				// (b) source-table reads pulled in by a CTAS / COPY-TO inner query walk.
				if (all_ok) {
					for (const auto &use : pre.tables) {
						if (!UseSatisfied(use, grants)) {
							all_ok = false;
							reason = std::string("acl:") + CapabilityName(use.cap) + ":" + use.ref;
							break;
						}
					}
				}
				// (c) external-resource policy uses (default-deny: empty list => deny).
				if (all_ok) {
					for (const auto &pu : pre.policy_uses) {
						bool matched = false;
						switch (pu.cap) {
						case Capability::READ_SOURCE:
							matched = UriPolicyMatch(pu.literal, st.SourcePoliciesForUser(id.user_id));
							break;
						case Capability::COPY_TO:
							matched = UriPolicyMatch(pu.literal, st.DestPoliciesForUser(id.user_id));
							break;
						case Capability::INSTALL:
							matched = ExtNameMatch(pu.literal, st.ExtPoliciesForUser(id.user_id));
							break;
						case Capability::ATTACH:
							matched = AttachTargetMatch(pu.literal, st.AttachPoliciesForUser(id.user_id));
							break;
						default:
							matched = false; // unknown policy capability -> fail closed
							break;
						}
						if (!matched) {
							all_ok = false;
							reason = std::string("policy:") + CapabilityName(pu.cap) + ":" + pu.literal;
							break;
						}
					}
				}
				// (d) column allow-lists + time windows on any source reads. The bind-walk
				// is skipped on this path, so use the parse-walk's own column collection
				// (its original domain) — strictly additional enforcement, never fewer
				// denials. (Until source policies are emitted in Phase 3 every read_source
				// is already denied at (c), so this path stays inert in prod today.)
				if (all_ok) {
					auto constraints = st.ConstraintsForUser(id.user_id);
					if (!EnforceConstraints(pre, constraints, st.LakeCatalog(), state, reason))
						all_ok = false;
				}
				allow = all_ok;
				if (allow)
					reason = "ok";
			} else if (!state.HasContext()) {
				reason = "no_context"; // bind-walk needs the live context; fail closed
			} else {
				// Bind with the agent's GRANTED schemas in scope. quack pushes direct refs
				// down as BARE table names (schema dropped): `remote.sales.orders` arrives as
				// `SELECT #1,#2,... FROM orders`. With only (lake,main) in the search path a
				// table living in `sales` can't bind -> bind_error -> fail-closed deny of a
				// legitimate granted read. The grants name every schema the agent may touch.
				auto grants = st.GrantsForUser(id.user_id);
				std::vector<std::string> lake_schemas;
				for (const auto &g : grants) {
					std::string sch = SchemaOfRef(g.resource_ref);
					bool seen = sch.empty();
					for (const auto &s : lake_schemas)
						if (s == sch) {
							seen = true;
							break;
						}
					if (!seen)
						lake_schemas.push_back(sch);
				}
				BoundAclAnalysis a = BindAnalyze(state.GetContext(), query, st.LakeCatalog(), lake_schemas);
				if (a.cls == AclClass::ALLOW_ALL) {
					allow = true;
					reason = "ok";
				} else if (a.cls == AclClass::FORBIDDEN || a.cls == AclClass::PARSE_ERR) {
					// Bind-and-walk could not bind the statement (un-bindable SQL, an
					// unresolvable column, or a forbidden bound operator) -> FAIL CLOSED
					// (deny). We deliberately do NOT fall back to the parse-walk's
					// table/column extraction here: that extraction is exactly what
					// bind-and-walk supersedes (its struct/star/positional/S8
					// approximations are the historical bypass surface), so trusting it
					// on the bind-failure path would reintroduce that surface. The
					// parse-walk's role is strictly the forbidden-CLASS pre-filter above.
					reason = a.reason;
				} else {
					// CHECK: every touched table must be covered by a grant. (`grants`
					// fetched above for the bind search-path schemas; reuse it.)
					bool all_ok = true;
					for (const auto &use : a.tables) {
						Capability missing;
						if (!BoundUseSatisfied(use, grants, &missing)) {
							all_ok = false;
							reason = std::string("acl:") + CapabilityName(missing) + ":" + use.ref;
							break;
						}
					}
					// Then the finer-grained constraints (column allow-lists + time
					// windows) layered on top of the table grants.
					if (all_ok) {
						auto constraints = st.ConstraintsForUser(id.user_id);
						if (!EnforceBoundConstraints(a, constraints, reason))
							all_ok = false;
					}
					allow = all_ok;
					if (allow)
						reason = "ok";
				}
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

// Parse 'HH:MM' or 'HH:MM:SS' (UTC) to minutes-of-day [0,1439]. Returns -1 for
// empty or malformed input (so the caller treats it as "no window").
static int32_t ParseHhMmToMinutes(const std::string &s) {
	if (s.empty())
		return -1;
	// HH:MM (5) or HH:MM:SS (8); only the HH:MM portion contributes to minutes.
	if (s.size() != 5 && s.size() != 8)
		return -1;
	if (s[2] != ':')
		return -1;
	if (s.size() == 8 && s[5] != ':')
		return -1;
	for (size_t i = 0; i < s.size(); i++) {
		if (i == 2 || i == 5)
			continue;
		if (s[i] < '0' || s[i] > '9')
			return -1;
	}
	int hh = (s[0] - '0') * 10 + (s[1] - '0');
	int mm = (s[3] - '0') * 10 + (s[4] - '0');
	if (hh < 0 || hh > 23 || mm < 0 || mm > 59)
		return -1;
	return static_cast<int32_t>(hh * 60 + mm);
}

// Split a comma-separated list, trim ASCII spaces, drop empties, lowercase each.
static std::vector<std::string> ParseColumnsCsv(const std::string &csv) {
	std::vector<std::string> out;
	size_t start = 0;
	while (start <= csv.size()) {
		size_t comma = csv.find(',', start);
		size_t end = comma == std::string::npos ? csv.size() : comma;
		size_t a = start, b = end;
		while (a < b && csv[a] == ' ')
			a++;
		while (b > a && csv[b - 1] == ' ')
			b--;
		if (b > a)
			out.push_back(LowerCopy(csv.substr(a, b - a)));
		if (comma == std::string::npos)
			break;
		start = comma + 1;
	}
	return out;
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
		// AddRoleGrant now takes a capability string and is fail-closed on unknown strings.
		// Legacy callers passing "read" / "write" continue to work unchanged.
		State::Get().AddRoleGrant(ArgStr(args.data[0], i), ArgStr(args.data[1], i), ArgStr(args.data[2], i));
		SetStrResult(result, i, "ok");
	}
}
// birdshot_add_role_grant_kind(role, resource_ref, cap, obj_kind) -> 'ok'
// Kind-aware grant push (spec §1c). obj_kind is one of table/view/sequence/function/
// type/schema/database (see ParseObjKind). Unknown cap OR kind -> the grant is dropped
// (fail-closed, under-grant). Legacy callers keep using the 3-arg birdshot_add_role_grant
// (defaults kind=table).
static void AddRoleGrantKindFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 4; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().AddRoleGrantKind(ArgStr(args.data[0], i), ArgStr(args.data[1], i), ArgStr(args.data[2], i),
		                              ArgStr(args.data[3], i));
		SetStrResult(result, i, "ok");
	}
}
// birdshot_set_grant_store(kind, target) -> effective kind ('memory' | 'table')
// Selects the grant-store backend at runtime (spec §0). 'memory' (default) keeps the
// current in-memory-only behavior; 'table' records an ATTACH target/DSN for durable
// write-through/load and reserves the protected `__birdshot` store catalog. An unknown
// kind falls back to 'memory' (fail-closed: never half-enable a store). This is a
// birdshot_* function so it is auto-denied on the wire by the parse-walk denylist.
static void SetGrantStoreFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 2; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		std::string kind = ArgNull(args.data[0], i) ? "" : ArgStr(args.data[0], i);
		std::string target = ArgNull(args.data[1], i) ? "" : ArgStr(args.data[1], i);
		std::string eff = State::Get().SetGrantStore(kind, target);
		SetStrResult(result, i, eff);
	}
}
// birdshot_add_grant_constraint(role, table_ref, columns_csv, window_start, window_end) -> 'ok'
// Row caps are intentionally absent (see GrantConstraint / contract C1b).
static void AddGrantConstraintFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 5; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		std::string role = ArgStr(args.data[0], i);
		std::string table_ref = ArgStr(args.data[1], i);
		std::string columns_csv = ArgNull(args.data[2], i) ? "" : ArgStr(args.data[2], i);
		std::string ws = ArgNull(args.data[3], i) ? "" : ArgStr(args.data[3], i);
		std::string we = ArgNull(args.data[4], i) ? "" : ArgStr(args.data[4], i);
		State::Get().AddGrantConstraint(role, table_ref, ParseColumnsCsv(columns_csv),
		                                ParseHhMmToMinutes(ws), ParseHhMmToMinutes(we));
		SetStrResult(result, i, "ok");
	}
}
// birdshot_set_lake_catalog(name) -> 'ok'
static void SetLakeCatalogFn(DataChunk &args, ExpressionState &state, Vector &result) {
	args.data[0].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().SetLakeCatalog(ArgNull(args.data[0], i) ? "" : ArgStr(args.data[0], i));
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
// birdshot_add_source_policy(role, pattern) -> 'ok'
// birdshot_add_dest_policy(role, pattern) -> 'ok'
// birdshot_add_ext_policy(role, pattern) -> 'ok'
// birdshot_add_attach_policy(role, pattern) -> 'ok'
//
// Non-catalog resource policy setters. `pattern` semantics per matcher in
// birdshot_acl.hpp: host/subdomain glob for URIs, exact name for extensions.
// These are additive into the staging snapshot and promoted by birdshot_commit_config().
// The policies are default-deny: an empty list means no access to the resource class.
static void AddSourcePolicyFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 2; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().AddSourcePolicy(ArgStr(args.data[0], i), ArgStr(args.data[1], i));
		SetStrResult(result, i, "ok");
	}
}
static void AddDestPolicyFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 2; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().AddDestPolicy(ArgStr(args.data[0], i), ArgStr(args.data[1], i));
		SetStrResult(result, i, "ok");
	}
}
static void AddExtPolicyFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 2; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().AddExtPolicy(ArgStr(args.data[0], i), ArgStr(args.data[1], i));
		SetStrResult(result, i, "ok");
	}
}
static void AddAttachPolicyFn(DataChunk &args, ExpressionState &state, Vector &result) {
	for (idx_t c = 0; c < 2; c++)
		args.data[c].Flatten(args.size());
	result.SetVectorType(VectorType::FLAT_VECTOR);
	for (idx_t i = 0; i < args.size(); i++) {
		State::Get().AddAttachPolicy(ArgStr(args.data[0], i), ArgStr(args.data[1], i));
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

// ======================= native GRANT / REVOKE statement ====================
//
// A DuckDB ParserExtension exposing real `GRANT …` / `REVOKE …` SQL. GRANT/REVOKE
// are Postgres keyword tokens with NO grammar production, so they fail DuckDB's
// built-in parser and are handed to this extension's parse_function.
//
// SECURITY (the whole point): registering this makes GRANT parse on EVERY
// connection, including untrusted agent wire connections. The wire authorize path
// (birdshot_authorize -> Analyze) denies GRANT fail-closed BEFORE any bind/plan/
// execution (the bare parser in Analyze throws -> `forbidden_grant_stmt` deny; the
// EXTENSION_STATEMENT case in AnalyzeStatement is defense-in-depth). Mutation of the
// grant store happens ONLY in this table function's EXECUTION callback — never in
// parse_function or plan_function (which run at parse/plan time and stay pure). So a
// GRANT only ever mutates when a TRUSTED connection (bare CLI / the gateway's own
// privileged connection, which does NOT self-authorize) actually executes it.
//
// Grammar supported (curated subset of PostgreSQL, spec §5/§8):
//   GRANT  <privlist|ALL [PRIVILEGES]> ON [<objkind>] <ref> TO   <grantee>[, …]
//   REVOKE <privlist|ALL [PRIVILEGES]> ON [<objkind>] <ref> FROM <grantee>[, …]
//   GRANT  <rolename> TO   <grantee>[, …]     (role membership — no ON)
//   REVOKE <rolename> FROM <grantee>[, …]
// privileges  -> SELECT/INSERT/UPDATE/DELETE/TRUNCATE/CREATE/DROP/ALTER/USAGE/EXECUTE
// <objkind>   -> optional TABLE/VIEW/SEQUENCE/FUNCTION/TYPE/SCHEMA/DATABASE (default TABLE)
// <grantee>   -> a bare identifier (a subject) or `ROLE <name>`
// FAIL-CLOSED: an unknown/unenforced privilege (TRIGGER/REFERENCES/…), or any
// malformed input, returns a DISPLAY_EXTENSION_ERROR — never a silent drop.
// DEFERRED (clear error): column lists `(c,…)`, ALL … IN SCHEMA, PUBLIC, CURRENT_USER,
// GRANTED BY, WITH GRANT OPTION, CASCADE/RESTRICT.

// One resolved store mutation, serialized into a single tab-delimited line. Codes:
//   g\t<role>\t<is_subject 0/1>\t<ref>\t<kind>\t<cap>   grant a privilege
//   r\t<role>\t<is_subject 0/1>\t<ref>\t<kind>\t<cap>   revoke a privilege
//   gr\t<subject>\t<role>                               grant role membership
//   rr\t<subject>\t<role>                               revoke role membership
// Identifiers come from a whitespace/comma tokenizer, so they never contain \t or \n.

static std::string GrantLower(const std::string &s) {
	std::string o = s;
	for (auto &c : o)
		c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
	return o;
}

// Tokenize into words, emitting ',' '(' ')' as standalone tokens and dropping ';'.
static vector<std::string> GrantTokenize(const std::string &sql) {
	vector<std::string> toks;
	std::string cur;
	auto flush = [&]() {
		if (!cur.empty()) {
			toks.push_back(cur);
			cur.clear();
		}
	};
	for (char c : sql) {
		unsigned char uc = static_cast<unsigned char>(c);
		if (::isspace(uc)) {
			flush();
		} else if (c == ',' || c == '(' || c == ')') {
			flush();
			toks.push_back(std::string(1, c));
		} else if (c == ';') {
			flush(); // statement terminator — separator only
		} else {
			cur += c;
		}
	}
	flush();
	return toks;
}

static bool GrantIsObjKind(const std::string &l) {
	return l == "table" || l == "view" || l == "sequence" || l == "function" || l == "type" || l == "schema" ||
	       l == "database";
}

// Map a PG privilege token -> birdshot capability spelling. Only the ENFORCED set.
static bool GrantPrivToCap(const std::string &priv, std::string &cap_out) {
	if (priv == "select")   { cap_out = "read";     return true; }
	if (priv == "insert")   { cap_out = "insert";   return true; }
	if (priv == "update")   { cap_out = "update";   return true; }
	if (priv == "delete")   { cap_out = "delete";   return true; }
	if (priv == "truncate") { cap_out = "truncate"; return true; }
	if (priv == "create")   { cap_out = "create";   return true; }
	if (priv == "drop")     { cap_out = "drop";     return true; }
	if (priv == "alter")    { cap_out = "alter";    return true; }
	if (priv == "usage")    { cap_out = "usage";    return true; }
	if (priv == "execute")  { cap_out = "execute";  return true; }
	return false; // TRIGGER / REFERENCES / MAINTAIN / typo / … -> caller rejects
}

// ALL [PRIVILEGES] expansion for an object class (the class's applicable caps).
static vector<std::string> GrantAllCapsForKind(const std::string &kind) {
	if (kind == "table" || kind == "view")
		return {"read", "insert", "update", "delete", "truncate"};
	if (kind == "sequence")
		return {"usage"};
	if (kind == "function")
		return {"execute"};
	if (kind == "type")
		return {"usage"};
	if (kind == "schema")
		return {"usage", "create"};
	if (kind == "database")
		return {"create"};
	return {};
}

struct BirdshotGrantParseData : public ParserExtensionParseData {
	std::string verb;        // "GRANT" | "REVOKE" (status row)
	vector<std::string> ops; // serialized mutation lines (see codes above)

	BirdshotGrantParseData(std::string verb_p, vector<std::string> ops_p)
	    : verb(std::move(verb_p)), ops(std::move(ops_p)) {
	}
	duckdb::unique_ptr<ParserExtensionParseData> Copy() const override {
		return make_uniq<BirdshotGrantParseData>(verb, ops);
	}
	std::string ToString() const override {
		return verb + "(" + std::to_string(ops.size()) + " ops)";
	}
};

// A grantee: a bare subject id, or a named role (`ROLE r`).
struct GrantGrantee {
	std::string name;
	bool is_subject;
};

// Parse a grantee list (comma-separated `<ident>` or `ROLE <ident>`). Returns false
// (caller rejects) on any malformed segment or an empty list.
static bool GrantParseGrantees(const vector<std::string> &toks, size_t begin, vector<GrantGrantee> &out) {
	vector<std::string> seg;
	auto emit = [&]() -> bool {
		if (seg.size() == 1) {
			out.push_back(GrantGrantee {seg[0], true});
		} else if (seg.size() == 2 && GrantLower(seg[0]) == "role") {
			out.push_back(GrantGrantee {seg[1], false});
		} else {
			return false;
		}
		seg.clear();
		return true;
	};
	for (size_t i = begin; i < toks.size(); i++) {
		if (toks[i] == ",") {
			if (!emit())
				return false;
		} else {
			seg.push_back(toks[i]);
		}
	}
	if (!seg.empty() && !emit())
		return false;
	return !out.empty();
}

static ParserExtensionParseResult BirdshotGrantParse(ParserExtensionInfo *, const string &query) {
	auto toks = GrantTokenize(query);
	if (toks.empty())
		return ParserExtensionParseResult(); // DISPLAY_ORIGINAL_ERROR (not ours)
	std::string t0 = GrantLower(toks[0]);
	bool is_grant = (t0 == "grant");
	bool is_revoke = (t0 == "revoke");
	if (!is_grant && !is_revoke)
		return ParserExtensionParseResult(); // not a GRANT/REVOKE — let DuckDB's error stand
	// From here it IS ours: every failure is a DISPLAY_EXTENSION_ERROR (fail-closed).
	auto err = [](const std::string &m) { return ParserExtensionParseResult("birdshot GRANT: " + m); };

	// Reject deferred / unsupported constructs up front (clear error, never a silent drop).
	for (const auto &tk : toks) {
		if (tk == "(" || tk == ")")
			return err("column lists are not supported yet");
		std::string l = GrantLower(tk);
		if (l == "public")
			return err("PUBLIC grantee is not supported yet");
		if (l == "current_user" || l == "current_role" || l == "session_user")
			return err("CURRENT_USER/CURRENT_ROLE grantee is not supported yet");
		if (l == "with")
			return err("WITH GRANT/ADMIN OPTION is not supported yet");
		if (l == "granted")
			return err("GRANTED BY is not supported yet");
		if (l == "cascade" || l == "restrict")
			return err("CASCADE/RESTRICT is not supported yet");
		if (l == "in")
			return err("ALL … IN SCHEMA is not supported yet");
	}

	const std::string kw = is_grant ? "to" : "from"; // GRANT … TO … / REVOKE … FROM …
	int on_idx = -1, kw_idx = -1;
	for (size_t i = 1; i < toks.size(); i++) {
		std::string l = GrantLower(toks[i]);
		if (l == "on" && on_idx < 0)
			on_idx = static_cast<int>(i);
		if (l == kw && kw_idx < 0)
			kw_idx = static_cast<int>(i);
	}
	if (kw_idx < 0)
		return err(std::string("expected ") + (is_grant ? "TO" : "FROM"));

	vector<std::string> ops;

	if (on_idx < 0) {
		// ---- role membership: GRANT <role> TO <grantees> / REVOKE <role> FROM <grantees> ----
		if (kw_idx != 2)
			return err("expected a single role name before " + GrantLower(kw));
		std::string role = toks[1];
		vector<GrantGrantee> grantees;
		if (!GrantParseGrantees(toks, static_cast<size_t>(kw_idx) + 1, grantees))
			return err("malformed grantee list");
		const char *code = is_grant ? "gr" : "rr";
		for (const auto &g : grantees)
			ops.push_back(std::string(code) + "\t" + g.name + "\t" + role);
	} else {
		// ---- privilege grant/revoke ----
		if (on_idx <= 1)
			return err("expected privileges before ON");
		if (kw_idx <= on_idx)
			return err(std::string("expected ") + (is_grant ? "TO" : "FROM") + " after the object");

		// privileges: toks(1 .. on_idx)
		bool all_mode = false;
		vector<std::string> caps;
		vector<std::string> priv_toks;
		for (int i = 1; i < on_idx; i++) {
			if (toks[i] == ",")
				continue;
			priv_toks.push_back(GrantLower(toks[i]));
		}
		if (priv_toks.empty())
			return err("expected a privilege list");
		if (priv_toks[0] == "all") {
			all_mode = true;
			if (priv_toks.size() == 2 && priv_toks[1] != "privileges")
				return err("unexpected token after ALL");
			if (priv_toks.size() > 2)
				return err("unexpected tokens after ALL PRIVILEGES");
		} else {
			for (const auto &p : priv_toks) {
				std::string cap;
				if (!GrantPrivToCap(p, cap))
					return err("unknown or unenforced privilege '" + p + "'");
				caps.push_back(cap);
			}
		}

		// object: toks(on_idx+1 .. kw_idx) = [<objkind>] <ref>
		vector<std::string> obj_toks;
		for (int i = on_idx + 1; i < kw_idx; i++) {
			if (toks[i] == ",")
				return err("only a single object is supported");
			obj_toks.push_back(toks[i]);
		}
		std::string kind = "table";
		std::string ref;
		if (obj_toks.size() == 1) {
			if (GrantIsObjKind(GrantLower(obj_toks[0])))
				return err("expected an object name after the object kind");
			ref = obj_toks[0];
		} else if (obj_toks.size() == 2 && GrantIsObjKind(GrantLower(obj_toks[0]))) {
			kind = GrantLower(obj_toks[0]);
			ref = obj_toks[1];
		} else {
			return err("could not parse the object reference");
		}

		if (all_mode) {
			caps = GrantAllCapsForKind(kind);
			if (caps.empty())
				return err("ALL PRIVILEGES is not supported for " + kind);
		}

		vector<GrantGrantee> grantees;
		if (!GrantParseGrantees(toks, static_cast<size_t>(kw_idx) + 1, grantees))
			return err("malformed grantee list");

		// NOTE (spec §1c, documented deferral): SCHEMA/DATABASE refs are stored VERBATIM.
		// Wildcard domination (`ON SCHEMA s` covering objects in s) is NOT expanded here —
		// a verbatim schema ref simply fails to RefMatch object uses, so it is inert
		// (under-grant = fail-safe). Enforced privilege×object combos on named TABLE/VIEW/
		// SEQUENCE/FUNCTION/TYPE objects are the covered set.
		const char *code = is_grant ? "g" : "r";
		for (const auto &g : grantees)
			for (const auto &cap : caps)
				ops.push_back(std::string(code) + "\t" + g.name + "\t" + (g.is_subject ? "1" : "0") + "\t" + ref +
				              "\t" + kind + "\t" + cap);
	}

	if (ops.empty())
		return err("nothing to do");
	return ParserExtensionParseResult(make_uniq<BirdshotGrantParseData>(is_grant ? "GRANT" : "REVOKE", std::move(ops)));
}

// ---- the exec table function (mutation happens HERE, at execution) ----------

struct BirdshotGrantExecBindData : public TableFunctionData {
	std::string ops_blob; // '\n'-joined op lines
	std::string verb;
	BirdshotGrantExecBindData(std::string ops_p, std::string verb_p)
	    : ops_blob(std::move(ops_p)), verb(std::move(verb_p)) {
	}
};
struct BirdshotGrantExecGlobalState : public GlobalTableFunctionState {
	bool done = false;
};

static void GrantSplit(const std::string &s, char delim, vector<std::string> &out) {
	out.clear();
	size_t start = 0;
	while (true) {
		size_t p = s.find(delim, start);
		if (p == std::string::npos) {
			out.push_back(s.substr(start));
			break;
		}
		out.push_back(s.substr(start, p - start));
		start = p + 1;
	}
}

// Apply the serialized ops to birdshot's live store. Called ONLY from execution.
// Reserved namespace for a subject's implicit singleton self-role (grantee `TO <subject>`).
// The leading 0x1D (GROUP SEPARATOR) control byte cannot appear in an admin-defined role
// name (role names are SQL identifiers / compiler-generated), so a subject id can NEVER
// collide with a role name. Without this, `GRANT p ON t TO alice` (subject) would write
// role_grants["alice"] and make subject "alice" a member of role "alice" — so a JWT `sub`
// equal to an existing admin role name would silently inherit that role's grants
// (escalation, advisor Finding A). subject ids are attacker-influenceable at some IdPs;
// role names are admin-chosen; nothing else guarantees them disjoint.
static std::string SubjectSelfRole(const std::string &subject) {
	return std::string("\x1d") + "subj:" + subject;
}

static void BirdshotApplyGrantOps(const std::string &blob) {
	auto &st = State::Get();
	vector<std::string> lines;
	GrantSplit(blob, '\n', lines);
	for (const auto &line : lines) {
		if (line.empty())
			continue;
		vector<std::string> f;
		GrantSplit(line, '\t', f);
		if (f.empty())
			continue;
		const std::string &code = f[0];
		if (code == "g" && f.size() == 6) {
			const std::string &name = f[1];
			bool is_subject = (f[2] == "1");
			// A subject grantee is stored under its NAMESPACED self-role (never the raw
			// subject id) so it can't collide with an admin role name. REVOKE below uses the
			// same mapping, so GRANT/REVOKE stay symmetric.
			std::string role_key = is_subject ? SubjectSelfRole(name) : name;
			if (is_subject)
				st.GrantRoleLive(name, role_key); // attach the subject to its namespaced self-role
			st.GrantLive(role_key, f[3], f[5], f[4]);
		} else if (code == "r" && f.size() == 6) {
			bool is_subject = (f[2] == "1");
			std::string role_key = is_subject ? SubjectSelfRole(f[1]) : f[1];
			st.RevokeLive(role_key, f[3], f[5], f[4]);
		} else if (code == "gr" && f.size() == 3) {
			st.GrantRoleLive(f[1], f[2]);
		} else if (code == "rr" && f.size() == 3) {
			st.RevokeRoleLive(f[1], f[2]);
		}
		// Any other shape: ignore (fail-closed; parse produced only the shapes above).
	}
}

static duckdb::unique_ptr<FunctionData> BirdshotGrantExecBind(ClientContext &, TableFunctionBindInput &input,
                                                              vector<LogicalType> &return_types,
                                                              vector<string> &names) {
	names.emplace_back("birdshot");
	return_types.emplace_back(LogicalType::VARCHAR);
	// PROTECTED INVARIANT — bind MUST stay side-effect-free. Quack prepares/binds at
	// PREPARE_REQUEST, which parses GRANT into an ExtensionStatement and calls this bind
	// BEFORE birdshot_authorize gets to deny it. The entire wire-safety argument (an agent
	// can't self-grant) rests on the mutation happening ONLY in the execution callback,
	// which the authorize deny prevents the wire from ever reaching. Moving any store
	// mutation into bind would run it at prepare-time, before the deny — a critical bypass.
	// NO mutation here — just carry the payload to execution.
	std::string ops = input.inputs[0].IsNull() ? "" : StringValue::Get(input.inputs[0]);
	std::string verb = input.inputs[1].IsNull() ? "" : StringValue::Get(input.inputs[1]);
	return make_uniq<BirdshotGrantExecBindData>(std::move(ops), std::move(verb));
}
static duckdb::unique_ptr<GlobalTableFunctionState> BirdshotGrantExecInit(ClientContext &, TableFunctionInitInput &) {
	return make_uniq<BirdshotGrantExecGlobalState>();
}
static void BirdshotGrantExecFunc(ClientContext &, TableFunctionInput &data_p, DataChunk &output) {
	auto &bind_data = data_p.bind_data->Cast<BirdshotGrantExecBindData>();
	auto &gstate = data_p.global_state->Cast<BirdshotGrantExecGlobalState>();
	if (gstate.done) {
		output.SetCardinality(0);
		return;
	}
	// THE mutation: applied exactly once, at execution, on the connection that
	// reached execution (a trusted path — the wire authorize path never gets here).
	BirdshotApplyGrantOps(bind_data.ops_blob);
	output.SetValue(0, 0, Value(bind_data.verb));
	output.SetCardinality(1);
	gstate.done = true;
}

static TableFunction BirdshotGrantExecTableFunction() {
	TableFunction tf("birdshot_grant_exec", {LogicalType::VARCHAR, LogicalType::VARCHAR}, BirdshotGrantExecFunc,
	                 BirdshotGrantExecBind, BirdshotGrantExecInit);
	return tf;
}

static ParserExtensionPlanResult BirdshotGrantPlan(ParserExtensionInfo *, ClientContext &,
                                                   duckdb::unique_ptr<ParserExtensionParseData> parse_data) {
	auto &pd = static_cast<BirdshotGrantParseData &>(*parse_data);
	// PURE: serialize the resolved ops into table-function parameters. No mutation here.
	std::string blob;
	for (size_t i = 0; i < pd.ops.size(); i++) {
		if (i)
			blob += "\n";
		blob += pd.ops[i];
	}
	ParserExtensionPlanResult result;
	result.function = BirdshotGrantExecTableFunction();
	result.parameters.push_back(Value(blob));
	result.parameters.push_back(Value(pd.verb));
	result.requires_valid_transaction = false; // birdshot state is separate from DuckDB storage
	result.return_type = StatementReturnType::QUERY_RESULT;
	return result;
}

static ParserExtension BirdshotGrantParserExtension() {
	ParserExtension ext;
	ext.parse_function = BirdshotGrantParse;
	ext.plan_function = BirdshotGrantPlan;
	return ext;
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
	Register(loader, "birdshot_add_role_grant_kind", {V, V, V, V}, V, AddRoleGrantKindFn);
	Register(loader, "birdshot_set_grant_store", {V, V}, V, SetGrantStoreFn);
	Register(loader, "birdshot_add_grant_constraint", {V, V, V, V, V}, V, AddGrantConstraintFn);
	Register(loader, "birdshot_set_lake_catalog", {V}, V, SetLakeCatalogFn);
	Register(loader, "birdshot_add_user_role", {V, V}, V, AddUserRoleFn);
	Register(loader, "birdshot_add_service_token", {V, V}, V, AddServiceTokenFn);
	// Non-catalog resource policy setters (READ_SOURCE / COPY_TO / INSTALL / ATTACH).
	Register(loader, "birdshot_add_source_policy", {V, V}, V, AddSourcePolicyFn);
	Register(loader, "birdshot_add_dest_policy",   {V, V}, V, AddDestPolicyFn);
	Register(loader, "birdshot_add_ext_policy",    {V, V}, V, AddExtPolicyFn);
	Register(loader, "birdshot_add_attach_policy", {V, V}, V, AddAttachPolicyFn);
	Register(loader, "birdshot_commit_config", {}, V, CommitConfigFn);

	// Revocation (instant in-memory denylist).
	Register(loader, "birdshot_revoke", {V, V, V, I}, V, RevokeFn);
	Register(loader, "birdshot_unrevoke", {V, V}, V, UnrevokeFn);

	// Audit + status.
	Register(loader, "birdshot_log_drain", {I}, V, LogDrainFn);
	Register(loader, "birdshot_status", {}, V, StatusFn);

	// Native GRANT / REVOKE statement (ParserExtension). Registered on the DBConfig so
	// `GRANT …` / `REVOKE …` parse + execute as real SQL. The wire authorize path
	// denies GRANT fail-closed (birdshot_acl.hpp); mutation happens only in the exec
	// table function (trusted-path execution).
	auto &config = DBConfig::GetConfig(loader.GetDatabaseInstance());
	ParserExtension::Register(config, BirdshotGrantParserExtension());
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
