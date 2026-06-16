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
#include "duckdb/parser/parsed_data/create_scalar_function_info.hpp"
#include "duckdb/execution/expression_executor_state.hpp"
#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/parser/column_list.hpp"
#include "duckdb/common/enums/on_entry_not_found.hpp"

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
void State::AddRoleGrant(const std::string &role, const std::string &table_ref, bool write) {
	std::lock_guard<std::mutex> lk(mtx_);
	staging_.role_grants[role].push_back({LowerCopy(table_ref), write});
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

// Grant check for a bound table use (mirrors UseSatisfied, which takes the
// parse-walk's TableUse; BoundTableUse carries the same ref/write).
static bool BoundUseSatisfied(const BoundTableUse &use, const std::vector<Grant> &grants) {
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
			} else if (!state.HasContext()) {
				reason = "no_context"; // bind-walk needs the live context; fail closed
			} else {
				BoundAclAnalysis a = BindAnalyze(state.GetContext(), query, st.LakeCatalog());
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
					// CHECK: every touched table must be covered by a grant.
					auto grants = st.GrantsForUser(id.user_id);
					bool all_ok = true;
					for (const auto &use : a.tables) {
						if (!BoundUseSatisfied(use, grants)) {
							all_ok = false;
							reason = std::string("acl:") + (use.write ? "w:" : "r:") + use.ref;
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
		std::string action = ArgStr(args.data[2], i);
		State::Get().AddRoleGrant(ArgStr(args.data[0], i), ArgStr(args.data[1], i), action == "write");
		SetStrResult(result, i, "ok");
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
	Register(loader, "birdshot_add_grant_constraint", {V, V, V, V, V}, V, AddGrantConstraintFn);
	Register(loader, "birdshot_set_lake_catalog", {V}, V, SetLakeCatalogFn);
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
