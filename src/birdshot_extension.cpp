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
std::string State::GrantStoreSchema() {
	std::lock_guard<std::mutex> lk(mtx_);
	return store_schema_;
}
bool State::IsProtectedCatalog(const std::string &catalog) {
	std::lock_guard<std::mutex> lk(mtx_);
	return !store_catalog_.empty() && catalog == store_catalog_;
}
bool State::SubjectHydrated(const std::string &sub) {
	std::lock_guard<std::mutex> lk(mtx_);
	return hydrated_subjects_.count(sub) != 0;
}
void State::MarkSubjectHydrated(const std::string &sub) {
	std::lock_guard<std::mutex> lk(mtx_);
	hydrated_subjects_.insert(sub);
}
void State::PoisonSubject(const std::string &sub) {
	std::lock_guard<std::mutex> lk(mtx_);
	poisoned_subjects_.insert(sub);
}
void State::UnpoisonSubject(const std::string &sub) {
	std::lock_guard<std::mutex> lk(mtx_);
	poisoned_subjects_.erase(sub);
}
bool State::SubjectPoisoned(const std::string &sub) {
	std::lock_guard<std::mutex> lk(mtx_);
	return poisoned_subjects_.count(sub) != 0;
}
bool State::GranteeKeyApplied(const std::string &key) {
	std::lock_guard<std::mutex> lk(mtx_);
	return applied_grantee_keys_.count(key) != 0;
}
void State::MarkGranteeKeyApplied(const std::string &key) {
	std::lock_guard<std::mutex> lk(mtx_);
	applied_grantee_keys_.insert(key);
}
int64_t State::HydratedEpoch() {
	std::lock_guard<std::mutex> lk(mtx_);
	return hydrated_epoch_;
}
void State::SetHydratedEpoch(int64_t epoch) {
	std::lock_guard<std::mutex> lk(mtx_);
	hydrated_epoch_ = epoch;
}
void State::MarkHydratedRoleKey(const std::string &role_key) {
	std::lock_guard<std::mutex> lk(mtx_);
	hydrated_role_keys_.insert(role_key);
}
void State::FlushHydrated() {
	std::lock_guard<std::mutex> lk(mtx_);
	// Erase ONLY the hydrated grant state, keyed by the role_keys hydration APPLY actually
	// wrote (hydrated_role_keys_, recorded from the g/gc/r/rc ops). This is deliberately NOT
	// a re-translation of the store (kind,grantee) columns: apply keys a grant by the stmt's
	// TO clause, so if the columns ever drift from the TO clause (a writer-contract
	// violation) a column-based flush would erase the WRONG key, leave the real grant behind,
	// and fail OPEN on the very REVOKE this gate exists to enforce (§12d). Erasing exactly the
	// applied role_keys makes that drift structurally incapable of stranding a live grant.
	// Only g/gc write role_grants/role_constraints; user_roles (membership) is intentionally
	// preserved (re-hydrate re-adds edges idempotently, appended `REVOKE ROLE` rows undo stale
	// ones). Scalar config (auth/JWKS/tokens/lake/*_policies) is never touched.
	for (const auto &role_key : hydrated_role_keys_) {
		live_.role_grants.erase(role_key);
		live_.role_denies.erase(role_key); // deny-wins ACL: flush hydrated denies too, or a
		                                   // store-side UNDENY/deletion would fail OPEN (§12d)
		live_.role_constraints.erase(role_key);
	}
	hydrated_role_keys_.clear();
	applied_grantee_keys_.clear();
	hydrated_subjects_.clear();
	poisoned_subjects_.clear();
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
                      const std::string &kind_str, bool grant_option, const std::string &grantor) {
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
	g.grant_option = grant_option; // stored, inert until Phase 3b (never affects Covers)
	g.grantor = grantor;           // stored, inert until cascade REVOKE (Phase 3b)
	live_.role_grants[role].push_back(g);
}
// Column-list GRANT: merge `columns` into the single existing column constraint for
// (role, table_ref), or create one. WIDENING semantics (PG-faithful) + exactly one
// column entry per (role,ref) avoids the AND-narrowing that appending a second entry
// would cause (each constraint is table-scoped and ANDed in EnforceBoundConstraints).
void State::GrantConstraintLive(const std::string &role, const std::string &table_ref,
                                const std::vector<std::string> &columns) {
	std::string ref = LowerCopy(table_ref);
	std::lock_guard<std::mutex> lk(mtx_);
	auto &vec = live_.role_constraints[role];
	// Find an existing COLUMN constraint (non-empty columns) for this exact ref to widen.
	for (auto &c : vec) {
		if (c.table_ref == ref && !c.columns.empty()) {
			for (const auto &col : columns) {
				bool present = false;
				for (const auto &e : c.columns)
					if (e == col) {
						present = true;
						break;
					}
				if (!present)
					c.columns.push_back(col);
			}
			return;
		}
	}
	// None yet: add a fresh column constraint (windows unset; window-only entries untouched).
	GrantConstraint c;
	c.table_ref = ref;
	c.columns = columns;
	c.window_start_min = -1;
	c.window_end_min = -1;
	vec.push_back(c);
}
// Inverse: erase every COLUMN constraint (non-empty columns) for (role, table_ref).
// Window-only constraints are preserved.
void State::RevokeConstraintLive(const std::string &role, const std::string &table_ref) {
	std::string ref = LowerCopy(table_ref);
	std::lock_guard<std::mutex> lk(mtx_);
	auto it = live_.role_constraints.find(role);
	if (it == live_.role_constraints.end())
		return;
	auto &v = it->second;
	v.erase(std::remove_if(v.begin(), v.end(),
	                       [&](const GrantConstraint &c) { return c.table_ref == ref && !c.columns.empty(); }),
	        v.end());
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
// Deny-wins ACL: append a Deny to live_.role_denies[role]. Mirror of GrantLive minus the
// inert delegation fields; cap/kind fail-closed (an unknown string is a no-op, never a deny
// that could unexpectedly forbid). resource_ref lowercased to match the RefMatch invariant.
void State::DenyLive(const std::string &role, const std::string &resource_ref, const std::string &cap_str,
                     const std::string &kind_str) {
	Capability cap;
	if (!ParseCapability(cap_str, cap))
		return; // unknown capability -> fail-closed no-op
	ObjKind kind;
	if (!ParseObjKind(kind_str, kind))
		return; // unknown object kind -> fail-closed no-op
	std::lock_guard<std::mutex> lk(mtx_);
	Deny d;
	d.resource_ref = LowerCopy(resource_ref);
	d.cap = cap;
	d.kind = kind;
	live_.role_denies[role].push_back(d);
}
// Inverse of DenyLive: erase every deny on `role` whose (ref, cap, kind) EXACTLY matches —
// exact-ref (not RefMatch), the inverse of one DenyLive (mirror of RevokeLive).
void State::UndenyLive(const std::string &role, const std::string &resource_ref, const std::string &cap_str,
                       const std::string &kind_str) {
	Capability cap;
	if (!ParseCapability(cap_str, cap))
		return; // unknown capability -> nothing could match; safe no-op
	ObjKind kind;
	if (!ParseObjKind(kind_str, kind))
		return;
	std::string ref = LowerCopy(resource_ref);
	std::lock_guard<std::mutex> lk(mtx_);
	auto it = live_.role_denies.find(role);
	if (it == live_.role_denies.end())
		return;
	auto &v = it->second;
	v.erase(std::remove_if(v.begin(), v.end(),
	                       [&](const Deny &d) {
		                       return d.resource_ref == ref && d.cap == cap && d.kind == kind;
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
	if (it != live_.user_roles.end()) {
		for (const auto &role : it->second) {
			auto git = live_.role_grants.find(role);
			if (git != live_.role_grants.end())
				out.insert(out.end(), git->second.begin(), git->second.end());
		}
	}
	// PUBLIC: grants on the reserved public pseudo-role are held implicitly by EVERY
	// authenticated identity — INCLUDING a user with no explicit roles, so this merge
	// runs unconditionally (do NOT early-return above on the no-roles case).
	auto pit = live_.role_grants.find(PublicRole());
	if (pit != live_.role_grants.end())
		out.insert(out.end(), pit->second.begin(), pit->second.end());
	return out;
}
std::vector<Deny> State::DeniesForUser(const std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	std::vector<Deny> out;
	auto it = live_.user_roles.find(user_id);
	if (it != live_.user_roles.end()) {
		for (const auto &role : it->second) {
			auto dit = live_.role_denies.find(role);
			if (dit != live_.role_denies.end())
				out.insert(out.end(), dit->second.begin(), dit->second.end());
		}
	}
	// PUBLIC denies apply to every identity too (same merge rule as grants, spec §8d).
	auto pit = live_.role_denies.find(PublicRole());
	if (pit != live_.role_denies.end())
		out.insert(out.end(), pit->second.begin(), pit->second.end());
	return out;
}
std::vector<GrantConstraint> State::ConstraintsForUser(const std::string &user_id) {
	std::lock_guard<std::mutex> lk(mtx_);
	std::vector<GrantConstraint> out;
	auto it = live_.user_roles.find(user_id);
	if (it != live_.user_roles.end()) {
		for (const auto &role : it->second) {
			auto cit = live_.role_constraints.find(role);
			if (cit != live_.role_constraints.end())
				out.insert(out.end(), cit->second.begin(), cit->second.end());
		}
	}
	// PUBLIC constraints apply to every identity too (same merge rule as grants).
	auto pit = live_.role_constraints.find(PublicRole());
	if (pit != live_.role_constraints.end())
		out.insert(out.end(), pit->second.begin(), pit->second.end());
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
	if (it != snap.user_roles.end()) {
		for (const auto &role : it->second) {
			auto pit = store.find(role);
			if (pit != store.end())
				out.insert(out.end(), pit->second.begin(), pit->second.end());
		}
	}
	// PUBLIC: reserved-pseudo-role resource policies apply to every identity (spec §8d).
	auto pubit = store.find(PublicRole());
	if (pubit != store.end())
		out.insert(out.end(), pubit->second.begin(), pubit->second.end());
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

// Split a dotted ref (`catalog.schema.table`, `schema.table`, or `table`) into its
// dot-separated segments. Used for segment-aware wildcard matching.
static std::vector<std::string> SplitRef(const std::string &ref) {
	std::vector<std::string> out;
	size_t start = 0;
	for (size_t i = 0; i <= ref.size(); i++) {
		if (i == ref.size() || ref[i] == '.') {
			out.push_back(ref.substr(start, i - start));
			start = i + 1;
		}
	}
	return out;
}

static bool RefMatch(const std::string &grant_ref, const std::string &use_ref) {
	if (grant_ref == "*")
		return true;
	// Catalog-agnostic SCHEMA wildcard `*.<schema>.*`. Minted ONLY by the native
	// `GRANT … ON ALL TABLES IN SCHEMA <s>` statement — NEVER by the control-plane
	// compiler (which emits 2-part `schema.table`, or expands wildcards into concrete
	// refs; see apps/control-api/src/lib/policy-compiler.ts). Matches any use ref whose
	// SCHEMA segment equals <schema>, across EVERY catalog: `*.main.*` matches a bare
	// `main.gtab` AND catalog-qualified `memory.main.gtab` / `lake.main.gtab`. The schema
	// segment is always the second-to-last: seg[0] of `schema.table`, seg[1] of
	// `catalog.schema.table`. This is deliberately distinct from a plain `schema.*` grant,
	// which stays CATALOG-SENSITIVE (below) so the compiler's fail-closed "literal wildcard
	// matches nothing at the bind-walk" invariant is preserved.
	{
		auto gseg = SplitRef(grant_ref);
		if (gseg.size() == 3 && gseg[0] == "*" && gseg[2] == "*" && !gseg[1].empty() && gseg[1] != "*") {
			auto useg = SplitRef(use_ref);
			return useg.size() >= 2 && useg[useg.size() - 2] == gseg[1];
		}
	}
	if (grant_ref.size() >= 2 && grant_ref.compare(grant_ref.size() - 2, 2, ".*") == 0) {
		std::string prefix = grant_ref.substr(0, grant_ref.size() - 1); // keep trailing '.'
		// A plain `.*` wildcard is CATALOG-SENSITIVE: use_ref must START with the prefix.
		// `lake.*` matches `lake.sales.orders`; `main.*` matches a BARE `main.gtab` but NOT a
		// catalog-qualified `lake.main.gtab`. The control-plane compiler RELIES on this — it
		// EXPANDS schema wildcards into concrete `schema.table` refs precisely because a bare
		// `schema.*` must not reach lake-qualified bound refs (so a cold-cache literal wildcard
		// fails CLOSED, not open). The cross-catalog schema wildcard is spelled `*.<schema>.*`
		// and handled above — never confuse the two.
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

// ---- deny-wins (spec DENY) -------------------------------------------------
//
// A table use is authorized iff (some GRANT matches) AND (no DENY matches). These
// answer the "no DENY matches" half. A deny MATCHES a use exactly like a grant covers
// one — RefMatch on ref AND KindMatch on kind AND Covers on cap — so `DENY WRITE`
// (umbrella) forbids every narrow DML need (deny broadly = fail-closed), and a deny
// overrides a grant regardless of grant specificity (deny-wins-always). Callers compute
// allow first, then apply a matching deny as an override to FORBIDDEN.

// Parse-plane (single-cap TableUse): true iff any deny matches this use.
static bool UseDenied(const TableUse &use, const std::vector<Deny> &denies) {
	for (const auto &d : denies) {
		if (!RefMatch(d.resource_ref, use.ref))
			continue;
		if (!KindMatch(d.kind, use.kind))
			continue;
		if (Covers(d.cap, use.cap))
			return true;
	}
	return false;
}

// Bind-plane (multi-cap BoundTableUse): a matching deny on ANY required cap forbids the
// WHOLE use — you cannot even READ a denied table as part of an `UPDATE … WHERE`. If
// `hit` is non-null it receives the FIRST denied cap (for the audit reason).
static bool BoundUseDenied(const BoundTableUse &use, const std::vector<Deny> &denies, Capability *hit = nullptr) {
	for (Capability need : use.caps) {
		for (const auto &d : denies) {
			if (!RefMatch(d.resource_ref, use.ref))
				continue;
			if (!KindMatch(d.kind, use.kind))
				continue;
			if (Covers(d.cap, need)) {
				if (hit)
					*hit = need;
				return true;
			}
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

// Lazy grant-store hydration (spec §12b/§12c). Defined after the native GRANT
// parser/applier it depends on (BirdshotGrantParse / BirdshotApplyGrantOps); forward-
// declared here so Authenticate can fire it at the handshake. On a "table" store it
// pulls the subject's GRANT rows (parameterized, parse-only, bounded, fail-closed) and
// applies them to live State so authorize stays a pure in-memory read.
static void HydrateSubject(ClientContext &ctx, const std::string &sub);

// §12d freshness gate. Reads the single-row store epoch from __birdshot_meta on
// birdshot's trusted internal connection (catalog-qualified like the grant pull, §12h).
// Returns false on ANY failure (missing table / query error / zero rows / NULL) so
// table-mode Authorize can fail CLOSED — epoch is REQUIRED in table mode; there is
// deliberately no "is freshness active" discriminator (that would be a fail-open trap).
static bool ReadStoreEpoch(ClientContext &ctx, int64_t &out);

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
			// §12d: hydration is now lazy-on-authorize (the freshness gate ensure_hydrates
			// each subject on every authorize), so authenticate only binds the session.
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
			// §12d: hydration is lazy-on-authorize; authenticate only binds the session.
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
		bool have_session = st.GetSession(sid, id);
		// §12d FRESHNESS GATE (table mode only): validate the in-memory cache against the
		// store epoch on EVERY authorize so a store-side REVOKE/GRANT change takes effect.
		// The flush is GLOBAL but re-hydrate is PER-SUBJECT, and the two are deliberately
		// SPLIT: when the epoch advances, FlushHydrated() drops the WHOLE hydrated cache
		// (A's, B's, shared-role, PUBLIC keys) and the epoch is bumped ONCE; HydrateSubject
		// then runs on EVERY authorize (below the epoch branch), re-populating each subject
		// lazily. Collapsing them — re-hydrating only the current subject inside the bump
		// branch — would silently strand every OTHER live session (they'd see
		// epoch==hydrated, skip the flush, and never get their erased keys re-applied). This
		// makes hydration lazy-on-authorize, so the Authenticate-time call is now redundant
		// and has been removed. FAIL-CLOSED: any epoch-read failure denies THIS call via a
		// dedicated reason (freshness_unavailable) — it must NOT poison (HydrateSubject
		// short-circuits on an already-hydrated subject BEFORE clearing poison, so poisoning
		// here on a transient read failure could stick closed until the next epoch bump).
		// Hoisted out of the deny-chain condition (no GNU statement-expression) so it stays
		// MSVC-portable and the gate reads top-to-bottom in this security-critical path.
		bool freshness_ok = true;
		if (have_session && st.GrantStoreKind() == "table") {
			if (!state.HasContext()) {
				freshness_ok = false; // no ClientContext -> can't reach store -> deny
			} else {
				int64_t store_epoch = 0;
				if (!ReadStoreEpoch(state.GetContext(), store_epoch)) {
					freshness_ok = false; // epoch REQUIRED in table mode -> fail closed
				} else {
					if (store_epoch > st.HydratedEpoch()) {
						st.FlushHydrated(); // GLOBAL: cold the whole cache once
						st.SetHydratedEpoch(store_epoch);
					}
					// PER-SUBJECT ensure_hydrated: no-op if already hydrated, otherwise
					// re-pulls this subject's current store rows (self-locks its apply;
					// FlushHydrated already released the State lock, so the brief flushed-
					// but-not-yet-repopulated window a concurrent authorize may observe reads
					// empty == denies == fail-safe).
					HydrateSubject(state.GetContext(), id.user_id);
				}
			}
		}
		if (!have_session) {
			reason = "no_session";
		} else if (!freshness_ok) {
			reason = "freshness_unavailable"; // §12d fail-closed: store epoch unreadable
		} else if (st.SubjectPoisoned(id.user_id)) {
			// §12b fail-closed: grant-store hydration failed for this subject at
			// authenticate (store unreachable / query error / unparseable row). The
			// session is bound but every authorization is DENIED until a successful
			// re-hydration clears the poison.
			reason = "hydration_failed";
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
				auto denies = st.DeniesForUser(id.user_id); // deny-wins ACL (spec DENY)
				bool all_ok = true;
				// (a) catalog DDL targets (CREATE/DROP/ALTER/DETACH + COPY-FROM write target).
				for (const auto &use : pre.cap_uses) {
					if (!UseSatisfied(use, grants)) {
						all_ok = false;
						reason = std::string("acl:") + CapabilityName(use.cap) + ":" + use.ref;
						break;
					}
					// deny-wins: a matching deny overrides the grant -> FORBIDDEN (spec DENY).
					if (UseDenied(use, denies)) {
						all_ok = false;
						reason = std::string("deny:") + CapabilityName(use.cap) + ":" + use.ref;
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
						if (UseDenied(use, denies)) { // deny-wins (spec DENY)
							all_ok = false;
							reason = std::string("deny:") + CapabilityName(use.cap) + ":" + use.ref;
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
					auto denies = st.DeniesForUser(id.user_id); // deny-wins ACL (spec DENY)
					bool all_ok = true;
					for (const auto &use : a.tables) {
						Capability missing;
						if (!BoundUseSatisfied(use, grants, &missing)) {
							all_ok = false;
							reason = std::string("acl:") + CapabilityName(missing) + ":" + use.ref;
							break;
						}
						// deny-wins: a matching deny on ANY required cap forbids the whole use (spec DENY).
						Capability dhit;
						if (BoundUseDenied(use, denies, &dhit)) {
							all_ok = false;
							reason = std::string("deny:") + CapabilityName(dhit) + ":" + use.ref;
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
//   GRANT  <priv[(cols)][,…]|ALL [PRIVILEGES]> ON <object> TO   <grantee>[, …] [WITH … OPTION] [GRANTED BY r]
//   REVOKE <priv[(cols)][,…]|ALL [PRIVILEGES]> ON <object> FROM <grantee>[, …] [GRANTED BY r] [CASCADE|RESTRICT]
//   GRANT  <rolename> TO   <grantee>[, …] [WITH ADMIN OPTION]   (role membership — no ON)
//   REVOKE <rolename> FROM <grantee>[, …]
// privileges  -> SELECT/INSERT/UPDATE/DELETE/TRUNCATE/CREATE/DROP/ALTER/USAGE/EXECUTE, each with an
//                optional per-privilege column list `(c1,c2)` (Tier 1; TABLE/VIEW only).
// <object>    -> [<objkind>] <ref>   (objkind = TABLE/VIEW/SEQUENCE/FUNCTION/TYPE/SCHEMA/DATABASE, default TABLE)
//                | ALL <TABLES|VIEWS|SEQUENCES|FUNCTIONS|TYPES> IN SCHEMA <schema>   -> wildcard ref <schema>.*
// <grantee>   -> a bare identifier (a subject), `ROLE <name>`, or PUBLIC (reserved pseudo-role).
// WITH GRANT OPTION / GRANTED BY <r> are STORED on the grant (inert until Phase 3b delegation).
// CASCADE/RESTRICT are ACCEPTED and applied as the plain scoped revoke (no dependency graph yet).
// FAIL-CLOSED: an unknown/unenforced privilege (TRIGGER/REFERENCES/…), an empty `()`, or any
// malformed input, returns a DISPLAY_EXTENSION_ERROR — never a silent drop.
// HONEST BLOCKER (clear error): CURRENT_USER/CURRENT_ROLE/SESSION_USER (no caller identity on
// this path); REVOKE GRANT OPTION FOR (needs the Phase 3b grant graph).

// One resolved store mutation, serialized into a single tab-delimited line. <flag> is the
// grantee kind: "1"=subject (namespaced self-role), "0"=named role, "p"=PUBLIC pseudo-role. Codes:
//   g\t<name>\t<flag>\t<ref>\t<kind>\t<cap>\t<grant_option 0/1>\t<grantor>   grant a privilege
//   r\t<name>\t<flag>\t<ref>\t<kind>\t<cap>                                 revoke a privilege
//   d\t<name>\t<flag>\t<ref>\t<kind>\t<cap>                                 deny a privilege (deny-wins)
//   ud\t<name>\t<flag>\t<ref>\t<kind>\t<cap>                                remove a deny (UNDENY)
//   gc\t<name>\t<flag>\t<ref>\t<col1,col2,…>                                install/widen a column allow-list
//   rc\t<name>\t<flag>\t<ref>                                              drop the column allow-list
//   gr\t<subject>\t<role>                                                  grant role membership
//   rr\t<subject>\t<role>                                                  revoke role membership
// Identifiers come from a whitespace/comma tokenizer, so they never contain \t or \n. Column
// names are lowercased and comma-joined into one field (no \t), split back in the applier.

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

// A grantee: a bare subject id, a named role (`ROLE r`), or the reserved PUBLIC
// pseudo-role (every authenticated identity, spec §8d).
struct GrantGrantee {
	std::string name;
	bool is_subject = false;
	bool is_public = false;
};

// Serialized grantee flag: "1"=subject (namespaced self-role), "0"=named role,
// "p"=PUBLIC (reserved pseudo-role). Decoded symmetrically in BirdshotApplyGrantOps.
static const char *GranteeFlag(const GrantGrantee &g) {
	if (g.is_public)
		return "p";
	return g.is_subject ? "1" : "0";
}

// Parse a grantee list (comma-separated `<ident>` | `ROLE <ident>` | `PUBLIC`), over
// toks[begin, end). Returns false (caller rejects) on any malformed segment or empty list.
static bool GrantParseGrantees(const vector<std::string> &toks, size_t begin, size_t end,
                               vector<GrantGrantee> &out) {
	vector<std::string> seg;
	auto emit = [&]() -> bool {
		if (seg.size() == 1 && GrantLower(seg[0]) == "public") {
			GrantGrantee g;
			g.is_public = true;
			out.push_back(g);
		} else if (seg.size() == 1) {
			GrantGrantee g;
			g.name = seg[0];
			g.is_subject = true;
			out.push_back(g);
		} else if (seg.size() == 2 && GrantLower(seg[0]) == "role") {
			GrantGrantee g;
			g.name = seg[1];
			out.push_back(g);
		} else {
			return false;
		}
		seg.clear();
		return true;
	};
	for (size_t i = begin; i < end && i < toks.size(); i++) {
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

// Map a plural object-class (in `ALL <plural> IN SCHEMA s`) to its singular ObjKind spelling.
static bool GrantPluralKind(const std::string &plural, std::string &singular_out) {
	if (plural == "tables")    { singular_out = "table";    return true; }
	if (plural == "views")     { singular_out = "view";     return true; }
	if (plural == "sequences") { singular_out = "sequence"; return true; }
	if (plural == "functions") { singular_out = "function"; return true; }
	if (plural == "types")     { singular_out = "type";     return true; }
	return false;
}

static ParserExtensionParseResult BirdshotGrantParse(ParserExtensionInfo *, const string &query) {
	auto toks = GrantTokenize(query);
	if (toks.empty())
		return ParserExtensionParseResult(); // DISPLAY_ORIGINAL_ERROR (not ours)
	std::string t0 = GrantLower(toks[0]);
	bool is_grant = (t0 == "grant");
	bool is_revoke = (t0 == "revoke");
	// Deny-wins ACL (spec DENY). DENY mirrors GRANT (adds a deny, uses TO); UNDENY mirrors
	// REVOKE (removes a deny, uses FROM). Everything else — privileges, ref, `ON [kind]`,
	// `ALL … IN SCHEMA`, grantee list (`ROLE`/`PUBLIC`) — reuses the GRANT/REVOKE parsing.
	bool is_deny = (t0 == "deny");
	bool is_undeny = (t0 == "undeny");
	bool is_deny_family = is_deny || is_undeny;
	bool uses_to = is_grant || is_deny;    // GRANT/DENY … TO …
	if (!is_grant && !is_revoke && !is_deny && !is_undeny)
		return ParserExtensionParseResult(); // not ours — let DuckDB's error stand
	// From here it IS ours: every failure is a DISPLAY_EXTENSION_ERROR (fail-closed).
	auto err = [](const std::string &m) { return ParserExtensionParseResult("birdshot GRANT: " + m); };

	// Precompute lowercased tokens for keyword tests (identifiers stay case-preserved in toks).
	vector<std::string> low(toks.size());
	for (size_t i = 0; i < toks.size(); i++)
		low[i] = GrantLower(toks[i]);

	// HONEST BLOCKER (spec "honest exception"): CURRENT_USER / CURRENT_ROLE / SESSION_USER
	// resolve to the identity RUNNING the GRANT. The trusted authoring path (gateway
	// privileged connection / bare CLI) has NO birdshot session identity in the table-
	// function ClientContext (birdshot's identity map is keyed by the quack session id,
	// unavailable here), so these are genuinely unresolvable on this path. Clear error
	// stating the reason — never a faked resolution.
	for (size_t i = 0; i < toks.size(); i++) {
		if (low[i] == "current_user" || low[i] == "current_role" || low[i] == "session_user")
			return err(low[i] + " needs a caller identity, available only once wire-authorized "
			                    "GRANT lands in Phase 3b");
	}

	// REVOKE GRANT OPTION FOR … strips only the delegation right — a grant-graph feature
	// that lands with Phase 3b. Deferred with a clear error (never silent).
	if (is_revoke && low.size() >= 4 && low[1] == "grant" && low[2] == "option" && low[3] == "for")
		return err("REVOKE GRANT OPTION FOR is not supported yet (Phase 3b delegation graph)");

	const std::string kw = uses_to ? "to" : "from"; // GRANT/DENY … TO … / REVOKE/UNDENY … FROM …
	// Locate ON and TO/FROM at PAREN DEPTH 0 so a column list `(c1,c2)` (its commas, and
	// pathologically an identifier spelled like a keyword) can't be mistaken for structure.
	int on_idx = -1, kw_idx = -1, depth = 0;
	for (size_t i = 1; i < toks.size(); i++) {
		if (toks[i] == "(") {
			depth++;
			continue;
		}
		if (toks[i] == ")") {
			if (depth > 0)
				depth--;
			continue;
		}
		if (depth != 0)
			continue;
		if (low[i] == "on" && on_idx < 0)
			on_idx = static_cast<int>(i);
		if (low[i] == kw && kw_idx < 0)
			kw_idx = static_cast<int>(i);
	}
	if (kw_idx < 0)
		return err(std::string("expected ") + (uses_to ? "TO" : "FROM"));

	// Trailing clauses after the grantee list: WITH … OPTION / GRANTED BY / CASCADE|RESTRICT.
	int tail_idx = -1;
	depth = 0;
	for (size_t i = static_cast<size_t>(kw_idx) + 1; i < toks.size(); i++) {
		if (toks[i] == "(") {
			depth++;
			continue;
		}
		if (toks[i] == ")") {
			if (depth > 0)
				depth--;
			continue;
		}
		if (depth != 0)
			continue;
		if (low[i] == "with" || low[i] == "granted" || low[i] == "cascade" || low[i] == "restrict") {
			tail_idx = static_cast<int>(i);
			break;
		}
	}
	size_t grantee_end = tail_idx < 0 ? toks.size() : static_cast<size_t>(tail_idx);

	// Parse the trailing clauses -> grant_option + grantor. CASCADE/RESTRICT are ACCEPTED
	// and applied as the ordinary scoped revoke: without a delegation dependency graph
	// (Phase 3b) RESTRICT is already the effective default (no tracked dependents to block)
	// and CASCADE reduces to the plain revoke. True cascade lands with the Phase 3b grant graph.
	bool grant_option = false;
	std::string grantor;
	if (tail_idx >= 0) {
		size_t i = static_cast<size_t>(tail_idx);
		while (i < toks.size()) {
			if (low[i] == "with") {
				// WITH GRANT OPTION (privilege) / WITH ADMIN OPTION (role membership).
				if (i + 2 < toks.size() && low[i + 2] == "option" && (low[i + 1] == "grant" || low[i + 1] == "admin")) {
					grant_option = true;
					i += 3;
					continue;
				}
				return err("malformed WITH … OPTION clause");
			} else if (low[i] == "granted") {
				if (i + 1 >= toks.size() || low[i + 1] != "by")
					return err("expected BY after GRANTED");
				size_t j = i + 2;
				if (j < toks.size() && low[j] == "role" && j + 1 < toks.size()) {
					grantor = toks[j + 1];
					j += 2;
				} else if (j < toks.size()) {
					grantor = toks[j];
					j += 1;
				} else {
					return err("GRANTED BY needs a grantor name");
				}
				i = j;
				continue;
			} else if (low[i] == "cascade" || low[i] == "restrict") {
				i += 1;
				continue;
			}
			return err("unexpected token '" + toks[i] + "' in trailing clause");
		}
	}

	// DENY/UNDENY are object/ref-level only: delegation is meaningless for a deny, so reject
	// WITH GRANT OPTION / GRANTED BY on a deny (never silently ignore an authoring clause).
	if (is_deny_family && (grant_option || !grantor.empty()))
		return err("WITH GRANT OPTION / GRANTED BY are not valid on DENY/UNDENY");

	vector<std::string> ops;

	if (on_idx < 0) {
		// ---- role membership: GRANT <role> TO <grantees> / REVOKE <role> FROM <grantees> ----
		// DENY has no role-membership form (deny-wins is object-level); require ON <object>.
		if (is_deny_family)
			return err("DENY/UNDENY requires ON <object>; role membership cannot be denied");
		if (kw_idx != 2)
			return err("expected a single role name before " + kw);
		std::string role = toks[1];
		vector<GrantGrantee> grantees;
		if (!GrantParseGrantees(toks, static_cast<size_t>(kw_idx) + 1, grantee_end, grantees))
			return err("malformed grantee list");
		const char *code = is_grant ? "gr" : "rr";
		for (const auto &g : grantees) {
			if (g.is_public)
				return err("PUBLIC is not a valid target for role membership");
			if (!g.is_subject)
				return err("role-to-role membership (ROLE …) is not modeled; grant to a subject");
			ops.push_back(std::string(code) + "\t" + g.name + "\t" + role);
		}
	} else {
		// ---- privilege grant/revoke ----
		if (on_idx <= 1)
			return err("expected privileges before ON");
		if (kw_idx <= on_idx)
			return err(std::string("expected ") + (uses_to ? "TO" : "FROM") + " after the object");

		// ---- privileges (each with an OPTIONAL column list): toks(1 .. on_idx) ----------
		// PG attaches a column list per-privilege (`SELECT (c1,c2)`). birdshot column allow-
		// lists are TABLE-scoped (not per-cap), so ALL column lists in one statement are
		// UNIONed into a single constraint (spec §8a; EnforceBoundConstraints). Consequence
		// (documented): a statement mixing a restricted priv with an unrestricted one on the
		// same table applies the union restriction to BOTH — over-restrict = under-grant = safe.
		bool all_mode = false;
		vector<std::string> caps;
		std::vector<std::string> col_union;
		{
			bool first = true;
			int i = 1;
			while (i < on_idx) {
				if (toks[i] == ",") {
					i++;
					continue;
				}
				if (first && low[i] == "all") {
					all_mode = true;
					int j = i + 1;
					if (j < on_idx && low[j] == "privileges")
						j++;
					for (int k = j; k < on_idx; k++)
						if (toks[k] != ",")
							return err("unexpected token after ALL PRIVILEGES");
					break;
				}
				first = false;
				std::string cap;
				if (!GrantPrivToCap(low[i], cap))
					return err("unknown or unenforced privilege '" + low[i] + "'");
				caps.push_back(cap);
				// optional column list immediately after this privilege
				if (i + 1 < on_idx && toks[i + 1] == "(") {
					int j = i + 2;
					bool any = false;
					while (j < on_idx && toks[j] != ")") {
						if (toks[j] == ",") {
							j++;
							continue;
						}
						if (toks[j] == "(")
							return err("nested parentheses in column list");
						std::string col = GrantLower(toks[j]);
						bool present = false;
						for (const auto &e : col_union)
							if (e == col) {
								present = true;
								break;
							}
						if (!present)
							col_union.push_back(col);
						any = true;
						j++;
					}
					if (j >= on_idx || toks[j] != ")")
						return err("unterminated column list");
					if (!any)
						return err("empty column list '()'");
					i = j + 1;
					continue;
				}
				i++;
			}
		}
		if (!all_mode && caps.empty())
			return err("expected a privilege list");

		// ---- object: toks(on_idx+1 .. kw_idx) --------------------------------------------
		//   [<objkind>] <ref>                              a named object
		//   ALL <TABLES|VIEWS|SEQUENCES|FUNCTIONS|TYPES> IN SCHEMA <schema>   -> wildcard <schema>.*
		vector<std::string> obj_toks;
		for (int i = on_idx + 1; i < kw_idx; i++) {
			if (toks[i] == ",")
				return err("only a single object is supported");
			obj_toks.push_back(toks[i]);
		}
		std::string kind = "table";
		std::string ref;
		if (!obj_toks.empty() && GrantLower(obj_toks[0]) == "all") {
			if (obj_toks.size() != 5 || GrantLower(obj_toks[2]) != "in" || GrantLower(obj_toks[3]) != "schema")
				return err("expected ALL <TABLES|VIEWS|SEQUENCES|FUNCTIONS|TYPES> IN SCHEMA <schema>");
			if (!GrantPluralKind(GrantLower(obj_toks[1]), kind))
				return err("unknown object class '" + GrantLower(obj_toks[1]) + "' after ALL");
			// Catalog-agnostic schema wildcard `*.<schema>.*` (see RefMatch): matches every
			// object in schema <s> across every catalog (bare or catalog-qualified use refs).
			// Deliberately DISTINCT from a plain `<s>.*` — which the control-plane compiler
			// emits with catalog-SENSITIVE semantics — so the two paths can never collide.
			ref = "*." + GrantLower(obj_toks[4]) + ".*";
		} else if (obj_toks.size() == 1) {
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

		// Column lists apply only to relation objects (table/view); the allow-list is a
		// read/write-column concept with no meaning on a sequence/function/type/schema.
		if (!col_union.empty() && !(kind == "table" || kind == "view"))
			return err("column lists apply only to TABLE/VIEW objects");

		// DEFERRED (spec): a column-list on DENY is out of scope — DENY is object/ref-level
		// only (deny a whole table/ref). Reject fail-closed rather than silently widen to
		// a whole-object deny. (Column-level deny can be added later parallel to the `gc` path.)
		if (is_deny_family && !col_union.empty())
			return err("column lists on DENY/UNDENY are out of scope (object-level DENY only)");

		vector<GrantGrantee> grantees;
		if (!GrantParseGrantees(toks, static_cast<size_t>(kw_idx) + 1, grantee_end, grantees))
			return err("malformed grantee list");

		// Op code: `d`=deny / `ud`=undeny (deny-wins ACL) — SAME 6-field layout as `r`
		// (name,flag,ref,kind,cap; no grant_option/grantor). `g`=grant (8-field) / `r`=revoke.
		const char *code = is_deny ? "d" : is_undeny ? "ud" : is_grant ? "g" : "r";
		const char *ccode = is_grant ? "gc" : "rc"; // column constraints: GRANT/REVOKE only
		for (const auto &g : grantees) {
			std::string flag = GranteeFlag(g);
			for (const auto &cap : caps) {
				if (is_grant)
					ops.push_back(std::string(code) + "\t" + g.name + "\t" + flag + "\t" + ref + "\t" + kind + "\t" +
					              cap + "\t" + (grant_option ? "1" : "0") + "\t" + grantor);
				else
					ops.push_back(std::string(code) + "\t" + g.name + "\t" + flag + "\t" + ref + "\t" + kind + "\t" +
					              cap);
			}
			// Column constraint (Tier 1). GRANT installs/widens the allow-list; REVOKE drops it.
			// The `rc` is ALWAYS paired with the base-cap `r` above, so REVOKE-with-columns
			// removes BOTH the grant and the restriction (over-revoke = under-grant = fail-safe;
			// a lone constraint-drop would fail OPEN and is never emitted).
			if (!col_union.empty()) {
				if (is_grant) {
					std::string cols;
					for (size_t k = 0; k < col_union.size(); k++) {
						if (k)
							cols += ",";
						cols += col_union[k];
					}
					ops.push_back(std::string(ccode) + "\t" + g.name + "\t" + flag + "\t" + ref + "\t" + cols);
				} else {
					ops.push_back(std::string(ccode) + "\t" + g.name + "\t" + flag + "\t" + ref);
				}
			}
		}
	}

	if (ops.empty())
		return err("nothing to do");
	std::string verb = is_deny ? "DENY" : is_undeny ? "UNDENY" : is_grant ? "GRANT" : "REVOKE";
	return ParserExtensionParseResult(make_uniq<BirdshotGrantParseData>(verb, std::move(ops)));
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

// SubjectSelfRole() is now header-inline (birdshot_state.hpp, next to PublicRole) so the
// apply path here and State::FlushHydrated share ONE (kind,grantee) -> role_key mapping.

// Resolve a serialized grantee (flag, name) to its role_key. "1"=subject -> namespaced
// self-role (collision-proof); "0"=named role -> the name; "p"=PUBLIC -> the reserved
// pseudo-role every identity holds. Mirrors GranteeFlag on the parse side.
static std::string GrantRoleKeyFor(const std::string &flag, const std::string &name) {
	if (flag == "p")
		return PublicRole();
	if (flag == "1")
		return SubjectSelfRole(name);
	return name; // "0" -> admin-defined role name
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
		// g\t<name>\t<flag>\t<ref>\t<kind>\t<cap>\t<grant_option 0/1>\t<grantor>  (8 fields)
		if (code == "g" && f.size() == 8) {
			const std::string &flag = f[2];
			std::string role_key = GrantRoleKeyFor(flag, f[1]);
			if (flag == "1")
				st.GrantRoleLive(f[1], role_key); // attach the subject to its namespaced self-role
			st.GrantLive(role_key, f[3], f[5], f[4], f[6] == "1", f[7]);
			// r\t<name>\t<flag>\t<ref>\t<kind>\t<cap>  (6 fields)
		} else if (code == "r" && f.size() == 6) {
			std::string role_key = GrantRoleKeyFor(f[2], f[1]);
			st.RevokeLive(role_key, f[3], f[5], f[4]);
			// d\t<name>\t<flag>\t<ref>\t<kind>\t<cap>  (6 fields) — deny-wins ACL (spec DENY)
		} else if (code == "d" && f.size() == 6) {
			const std::string &flag = f[2];
			std::string role_key = GrantRoleKeyFor(flag, f[1]);
			if (flag == "1")
				st.GrantRoleLive(f[1], role_key); // attach subject to self-role so DeniesForUser resolves
			st.DenyLive(role_key, f[3], f[5], f[4]);
			// ud\t<name>\t<flag>\t<ref>\t<kind>\t<cap>  (6 fields) — remove a deny (UNDENY)
		} else if (code == "ud" && f.size() == 6) {
			std::string role_key = GrantRoleKeyFor(f[2], f[1]);
			st.UndenyLive(role_key, f[3], f[5], f[4]);
			// gc\t<name>\t<flag>\t<ref>\t<cols_csv>  (5 fields) — column-list constraint (install/widen)
		} else if (code == "gc" && f.size() == 5) {
			const std::string &flag = f[2];
			std::string role_key = GrantRoleKeyFor(flag, f[1]);
			if (flag == "1")
				st.GrantRoleLive(f[1], role_key); // ensure subject membership even on a constraint-only op
			vector<std::string> cols;
			GrantSplit(f[4], ',', cols);
			st.GrantConstraintLive(role_key, f[3], cols);
			// rc\t<name>\t<flag>\t<ref>  (4 fields) — drop the column-list constraint
		} else if (code == "rc" && f.size() == 4) {
			std::string role_key = GrantRoleKeyFor(f[2], f[1]);
			st.RevokeConstraintLive(role_key, f[3]);
			// gr/rr\t<subject>\t<role>  (3 fields) — role membership
		} else if (code == "gr" && f.size() == 3) {
			st.GrantRoleLive(f[1], f[2]);
		} else if (code == "rr" && f.size() == 3) {
			st.RevokeRoleLive(f[1], f[2]);
		}
		// Any other shape: ignore (fail-closed; parse produced only the shapes above).
	}
}

// ---- lazy grant-store hydration (spec §12b/§12c) ---------------------------
// Called from birdshot_authenticate the first time a token binds subject `sub`. On a
// "table" store it BFS-pulls sub's grant rows (∪ PUBLIC ∪ transitively each granted
// role's rows), parses each row through the SAME native path as an interactive GRANT
// (parse-ONLY — never con.run(stmt)), and applies the result to live State so authorize
// stays a pure in-memory read. Every failure mode (store unreachable, query error, a row
// that is not a clean GRANT/REVOKE, depth blowout) FAILS CLOSED: the subject is poisoned
// and Authorize denies it. The nested Connection is birdshot's trusted internal path —
// the authorize hook gates only the quack wire, never this connection, so the protected
// __birdshot_grants is readable here (de-risked) while unaddressable over the wire.
static void HydrateSubject(ClientContext &ctx, const std::string &sub) {
	auto &st = State::Get();
	if (st.GrantStoreKind() != "table")
		return; // no store configured -> interactive/in-memory mode, unchanged (§12c)
	if (st.SubjectHydrated(sub))
		return; // already pulled this subject's grants
	// NB (TOCTOU, benign): two concurrent authenticate calls for the same fresh subject
	// can both pass this check and the per-key GranteeKeyApplied guard, double-applying a
	// key. Same grantee, same semantics — duplicate grants, never an over-grant. A real
	// serialization (or the phase-4 epoch refresh) would close it; not load-bearing here.

	// Fresh attempt: clear any prior poison so a repaired store can re-hydrate.
	st.UnpoisonSubject(sub);

	struct Item {
		std::string kind;    // "subject" | "role" | "public"
		std::string grantee; // raw id ("" for public)
		int depth;
	};
	const int kMaxDepth = 32; // A∈B,B∈A terminates via `visited`; depth is a runaway guard
	std::vector<Item> work;
	work.push_back(Item {"subject", sub, 0});
	work.push_back(Item {"public", "", 0});
	std::set<std::string> visited; // cycle detection within this BFS

	try {
		// Trusted internal connection (NOT the wire path). Parameterized pull only:
		// `sub`/grantee is attacker-controlled and is NEVER concatenated into SQL.
		duckdb::Connection con(*ctx.db);

		// Catalog-qualify the pull by the configured store catalog (§12h). For the
		// production Postgres backend the store table lives in an ATTACHed protected
		// catalog (`__birdshot.<schema>.__birdshot_grants`), so an unqualified
		// `__birdshot_grants` — which resolves only in the default `memory.main` — would
		// miss it. Discriminate on ACTUAL attachment: if a catalog named `store_catalog_`
		// is attached, fully qualify `<catalog>.<schema>.__birdshot_grants`; otherwise
		// (LOCAL backend, table in `memory.main`) keep the bare name. This keeps the
		// local-backend path (and its sqllogictest) working unchanged while making the
		// Postgres backend resolve — WITHOUT ever putting the store catalog in the agent
		// search path (which would expose it to wire queries). The catalog/schema are
		// birdshot-internal constants (never attacker input); only `sub` is bound.
		std::string store_cat = st.GrantStoreCatalog();
		std::string table_ref = "__birdshot_grants";
		if (!store_cat.empty() && Catalog::GetCatalogEntry(ctx, store_cat)) {
			std::string schema = st.GrantStoreSchema();
			table_ref = "\"" + store_cat + "\".\"" + schema + "\".\"__birdshot_grants\"";
		}
		// ORDER BY version so an append-only writer's GRANT then a later REVOKE in the same
		// key apply in issue order (§12d): the REVOKE's RevokeLive removes the grant only if
		// it lands AFTER it. version is the monotonic per-mutation counter (§12a).
		auto prep = con.Prepare("SELECT stmt FROM " + table_ref +
		                        " WHERE grantee_kind = ? AND grantee = ? ORDER BY version");
		if (!prep || prep->HasError()) {
			st.PoisonSubject(sub);
			return;
		}
		while (!work.empty()) {
			Item it = work.back();
			work.pop_back();
			if (it.depth > kMaxDepth) {
				st.PoisonSubject(sub); // pathological role chain -> fail closed
				return;
			}
			std::string vkey = it.kind + std::string("\x1f") + it.grantee;
			if (visited.count(vkey))
				continue;
			visited.insert(vkey);

			duckdb::vector<Value> params;
			params.push_back(Value(it.kind));
			params.push_back(Value(it.kind == "public" ? std::string() : it.grantee));
			auto res = prep->Execute(params, false);
			if (!res || res->HasError()) {
				st.PoisonSubject(sub);
				return;
			}

			// Collect + parse ALL rows for this key BEFORE applying any (per-key all-or-
			// nothing: one unparseable row denies the subject without half-applying the key).
			std::vector<std::string> key_ops;       // serialized grant ops for this key
			std::vector<std::string> pending_roles; // transitive role memberships discovered
			bool key_ok = true;
			while (key_ok) {
				auto chunk = res->Fetch();
				if (!chunk || chunk->size() == 0)
					break;
				chunk->Flatten();
				for (idx_t r = 0; r < chunk->size(); r++) {
					Value v = chunk->GetValue(0, r);
					if (v.IsNull()) {
						key_ok = false; // null stmt -> fail closed
						break;
					}
					std::string stmt = StringValue::Get(v);
					// PARSE-ONLY (§12b): a row that is not a clean GRANT/REVOKE ->
					// DISPLAY_ORIGINAL_ERROR (non-grant) or DISPLAY_EXTENSION_ERROR
					// (malformed grant); neither is PARSE_SUCCESSFUL -> fail closed.
					auto pr = BirdshotGrantParse(nullptr, stmt);
					if (pr.type != ParserExtensionResultType::PARSE_SUCCESSFUL || !pr.parse_data) {
						key_ok = false;
						break;
					}
					auto &pd = static_cast<BirdshotGrantParseData &>(*pr.parse_data);
					for (const auto &op : pd.ops) {
						key_ops.push_back(op);
						// role membership op "gr\t<subject>\t<role>" -> pull that role next.
						if (op.rfind("gr\t", 0) == 0) {
							vector<std::string> f;
							GrantSplit(op, '\t', f);
							if (f.size() == 3)
								pending_roles.push_back(f[2]);
						}
					}
				}
			}
			if (!key_ok) {
				st.PoisonSubject(sub);
				return;
			}

			// Apply keyed to the grantee NAMED in each stmt (BirdshotApplyGrantOps does this),
			// exactly once process-wide: a shared PUBLIC/role key must not accumulate a
			// duplicate GrantLive per authenticating subject. Membership edges still come from
			// each subject's own (always-queried) subject rows, so shared roles resolve.
			if (!key_ops.empty() && !st.GranteeKeyApplied(vkey)) {
				std::string blob;
				for (size_t k = 0; k < key_ops.size(); k++) {
					if (k)
						blob += "\n";
					blob += key_ops[k];
				}
				BirdshotApplyGrantOps(blob); // Live methods self-lock; do NOT hold a State lock here
				// Record the role_keys apply actually wrote (same GrantRoleKeyFor mapping the
				// apply path uses) so FlushHydrated erases EXACTLY these — never a re-translation
				// of the store columns, which could drift from the stmt's TO clause and fail OPEN
				// on REVOKE (§12d). g/gc/r/rc/d/ud all carry (name=f[1], flag=f[2]); d/ud key
				// role_denies (deny-wins ACL) which flush must also drop; gr/rr touch only
				// user_roles (preserved by flush) so they are skipped.
				for (const auto &op : key_ops) {
					vector<std::string> f;
					GrantSplit(op, '\t', f);
					if (f.size() >= 3 && (f[0] == "g" || f[0] == "gc" || f[0] == "r" || f[0] == "rc" ||
					                      f[0] == "d" || f[0] == "ud"))
						st.MarkHydratedRoleKey(GrantRoleKeyFor(f[2], f[1]));
				}
				st.MarkGranteeKeyApplied(vkey);
			}

			for (const auto &role : pending_roles)
				work.push_back(Item {"role", role, it.depth + 1});
		}
	} catch (...) {
		st.PoisonSubject(sub); // any store/exec error -> fail closed (never proceed partial)
		return;
	}

	st.MarkSubjectHydrated(sub);
}

// §12d freshness signal. Reads the single-row store epoch from __birdshot_meta on
// birdshot's trusted internal connection — the SAME connection/catalog discipline as
// HydrateSubject's grant pull (§12h): if a catalog named store_catalog_ is ATTACHed the
// table is fully qualified `<catalog>.<schema>.__birdshot_meta`, otherwise (local backend)
// the bare name resolves in memory.main. Catalog/schema are birdshot-internal constants
// (never attacker input) and there are no bound parameters, so a direct Query is safe.
// FAIL-CLOSED contract (§12d): ANY failure — missing table, prepare/execute error, zero
// rows, or NULL epoch — returns false, and the caller denies this authorize. There is no
// attempt to distinguish "meta table absent" from "store unreachable" (that discriminator
// is a fail-OPEN trap). TODO(perf): reuse one long-lived internal connection instead of
// opening one per authorize — correctness first (advisor-sequenced).
static bool ReadStoreEpoch(ClientContext &ctx, int64_t &out) {
	auto &st = State::Get();
	try {
		duckdb::Connection con(*ctx.db);
		std::string store_cat = st.GrantStoreCatalog();
		std::string table_ref = "__birdshot_meta";
		if (!store_cat.empty() && Catalog::GetCatalogEntry(ctx, store_cat)) {
			std::string schema = st.GrantStoreSchema();
			table_ref = "\"" + store_cat + "\".\"" + schema + "\".\"__birdshot_meta\"";
		}
		auto res = con.Query("SELECT epoch FROM " + table_ref);
		if (!res || res->HasError())
			return false;
		auto chunk = res->Fetch();
		if (!chunk || chunk->size() == 0)
			return false; // zero rows == read failure -> fail closed
		chunk->Flatten();
		Value v = chunk->GetValue(0, 0);
		if (v.IsNull())
			return false; // NULL epoch == read failure -> fail closed
		out = v.GetValue<int64_t>();
		return true;
	} catch (...) {
		return false; // any store/exec error -> fail closed
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
