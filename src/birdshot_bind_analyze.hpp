#pragma once

// ============================================================================
// Bind-and-walk ACL extraction (supersedes the parse-walk's table/column
// extraction — see contract C1g / C1g-PROBE).
//
// Instead of hand-reimplementing DuckDB's name resolver (struct flattening,
// star scoping, positional `#N`, CTE scoping, multi-table unqualified
// resolution — every one a past adversarial bug), we BIND the query with the
// real binder (NO optimizer) and walk the BOUND plan, where tables, columns,
// stars and positionals are already resolved against the catalog.
//
// The walk produces `BoundAclAnalysis`: one `BoundTableUse` per distinct base
// table actually scanned (keyed by the plan's `table_index`), carrying the real
// catalog/schema/name + the set of REAL column names read from that table. The
// linkage key is `table_index` — each `BoundColumnRefExpression.binding` carries
// the table_index of the GET it reads, so column attribution is exact and the
// parse-walk's qualifier/alias matching (and the whole single- vs multi-table
// split) dissolves.
//
// SECURITY: binding untrusted SQL has bind-time side effects (replacement scans,
// extension autoload, table-function bind doing file I/O). The gateway disables
// file/extension access on the hook context (enable_external_access=false +
// autoload/autoinstall=false, Phase-3 boot). This walker additionally fails
// CLOSED on any bound operator that can reference a table but isn't explicitly
// handled (writes/DDL/COPY/unknown) — a silently-skipped operator would be a
// default-allow bypass.
//
// The bind itself runs with NO lock (model: json_serialize_plan.cpp): a
// standalone Parser + Binder::CreateBinder(ctx)->Bind(stmt). It NEVER runs the
// optimizer (which folds struct_extract chains and destroys recoverable base
// columns) and NEVER runs ColumnBindingResolver (which rewrites BoundColumnRef
// into BoundReference and destroys the bindings we read).
// ============================================================================

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "duckdb.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/client_data.hpp"
#include "duckdb/catalog/catalog_search_path.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/planner/binder.hpp"
#include "duckdb/planner/bound_statement.hpp"
#include "duckdb/planner/logical_operator.hpp"
#include "duckdb/planner/logical_operator_visitor.hpp"
#include "duckdb/planner/operator/logical_get.hpp"
#include "duckdb/planner/operator/logical_insert.hpp"
#include "duckdb/planner/operator/logical_update.hpp"
#include "duckdb/planner/operator/logical_delete.hpp"
#include "duckdb/planner/operator/logical_create_table.hpp"
#include "duckdb/planner/expression/bound_columnref_expression.hpp"
#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/parser/column_list.hpp"
#include "duckdb/common/enums/statement_type.hpp"

#include "birdshot_acl.hpp" // AclClass, TableUse, AclAnalysis, LowerCopy, QualifyRef, IsSystemRef

namespace birdshot {

// A base table actually referenced by the bound plan, with the real columns
// read from it. `read_cols` holds lowercased catalog column NAMES (struct fields
// and positionals already resolved to their base column). For a write target the
// table is recorded with write=true and (for the column allow-list, which is a
// read concept) no read columns charged.
struct BoundTableUse {
	std::string ref; // "[catalog.][schema.]table", lowercased — for RefMatch
	std::string catalog;
	std::string schema;
	std::string table;
	bool write = false;
	std::unordered_set<std::string> read_cols; // lowercased real column names
};

struct BoundAclAnalysis {
	AclClass cls = AclClass::PARSE_ERR;
	std::vector<BoundTableUse> tables;
	std::string reason;
};

// ---- the collect-only plan visitor -----------------------------------------
//
// Mirrors ColumnBindingResolver's traversal but ONLY collects: it records every
// LogicalGet (table_index -> &LogicalGet) and every BoundColumnRef binding, and
// returns the original expression unchanged (never rewrites). It also captures
// write/DDL target tables and trips `forbidden` on any operator that can touch a
// table but isn't handled here.
class BoundAclVisitor : public duckdb::LogicalOperatorVisitor {
public:
	// table_index -> the GET that produced it (built during the walk).
	std::unordered_map<duckdb::idx_t, duckdb::LogicalGet *> gets;
	// every column binding seen (resolved to names in a SECOND pass).
	std::vector<duckdb::ColumnBinding> bindings;
	// write/DDL target tables captured directly from their bound operators.
	std::vector<BoundTableUse> write_tables;
	bool forbidden = false;
	std::string reason;

	void VisitOperator(duckdb::LogicalOperator &op) override {
		using namespace duckdb;
		switch (op.type) {
		case LogicalOperatorType::LOGICAL_GET: {
			auto &get = op.Cast<LogicalGet>();
			gets[get.table_index] = &get;
			break;
		}
		case LogicalOperatorType::LOGICAL_INSERT: {
			auto &ins = op.Cast<LogicalInsert>();
			// INSERT target columns: column_index_map maps each physical column to its
			// value index (INVALID_INDEX = not written). A written column counts as a
			// touched column (charged against the allow-list). An empty map means "all
			// columns" (bare `INSERT INTO t VALUES ...`) — charge them all.
			std::vector<std::string> cols;
			const ColumnList &cl = ins.table.GetColumns();
			for (auto &pc : cl.Physical()) {
				PhysicalIndex pidx = pc.Physical();
				bool written = ins.column_index_map.empty() ||
				               (pidx.index < ins.column_index_map.size() &&
				                ins.column_index_map[pidx] != DConstants::INVALID_INDEX);
				if (written)
					cols.push_back(LowerCopy(pc.GetName()));
			}
			AddWriteTable(ins.table, cols);
			break;
		}
		case LogicalOperatorType::LOGICAL_UPDATE: {
			auto &upd = op.Cast<LogicalUpdate>();
			// UPDATE SET target columns (PhysicalIndex) -> names; each is a written
			// column charged against the allow-list (column ACLs are not action-scoped).
			std::vector<std::string> cols;
			const ColumnList &cl = upd.table.GetColumns();
			for (auto &pidx : upd.columns)
				cols.push_back(LowerCopy(cl.GetColumn(pidx).GetName()));
			AddWriteTable(upd.table, cols);
			break;
		}
		case LogicalOperatorType::LOGICAL_DELETE: {
			auto &del = op.Cast<LogicalDelete>();
			AddWriteTable(del.table, {});
			break;
		}
		case LogicalOperatorType::LOGICAL_CREATE_TABLE: {
			// CTAS / CREATE TABLE: the new table is a write target. Its source
			// SELECT (if any) is a child operator walked below as ordinary GETs.
			auto &ct = op.Cast<LogicalCreateTable>();
			AddCreateTable(ct);
			break;
		}
		case LogicalOperatorType::LOGICAL_COPY_TO_FILE:
			// COPY ... TO '<file>' exfiltrates a (possibly granted) table to a file
			// outside the ACL surface. Even with enable_external_access=false (which
			// blocks it at bind) we fail closed here so the posture doesn't depend on
			// that one setting.
			forbidden = true;
			reason = "forbidden_copy_to_file";
			break;
		case LogicalOperatorType::LOGICAL_DELIM_GET:
			// A delim-get materializes a correlated duplicate-eliminated set; its
			// columns are charged via the originating GET's bindings, so it carries no
			// new base-table read. (Listed explicitly so it is NOT treated as unknown.)
			break;
		default:
			break;
		}
		// Visit this operator's own expressions (collects BoundColumnRefs), then
		// recurse into children (so child GETs are captured).
		VisitOperatorExpressions(op);
		VisitOperatorChildren(op);
	}

	duckdb::unique_ptr<duckdb::Expression>
	VisitReplace(duckdb::BoundColumnRefExpression &expr, duckdb::unique_ptr<duckdb::Expression> *expr_ptr) override {
		bindings.push_back(expr.binding);
		return nullptr; // keep original — do NOT rewrite (would destroy bindings)
	}

private:
	void AddWriteTable(duckdb::TableCatalogEntry &tbl, const std::vector<std::string> &write_cols) {
		BoundTableUse u;
		u.catalog = LowerCopy(tbl.ParentCatalog().GetName());
		u.schema = LowerCopy(tbl.ParentSchema().name);
		u.table = LowerCopy(tbl.name);
		u.ref = QualifyRef(u.catalog, u.schema, u.table);
		u.write = true;
		for (auto &c : write_cols)
			u.read_cols.insert(c); // written columns are charged like read columns
		if (!IsSystemRef(u.catalog, u.schema, u.table))
			write_tables.push_back(std::move(u));
	}
	void AddCreateTable(duckdb::LogicalCreateTable &ct) {
		using namespace duckdb;
		auto &base = *ct.info->base;
		auto &info = base.Cast<CreateTableInfo>();
		BoundTableUse u;
		u.catalog = LowerCopy(info.catalog);
		u.schema = LowerCopy(info.schema);
		u.table = LowerCopy(info.table);
		u.ref = QualifyRef(u.catalog, u.schema, u.table);
		u.write = true;
		if (!IsSystemRef(u.catalog, u.schema, u.table))
			write_tables.push_back(std::move(u));
	}
};

// Resolve one binding to (table_index present in gets) + real column name via the
// VERIFIED recipe: names[ GetColumnIds()[column_index].GetPrimaryIndex() ].
// Returns false (caller decides) for a binding into a non-GET table_index (a
// projection/CTE-scan/correlated index — its real base read is charged via the
// GET it ultimately reads). `fatal` is set true ONLY when the binding lands on a
// REAL base table GET but cannot be resolved to a column name (out-of-range /
// no primary index) — that must fail closed.
inline bool ResolveBinding(const std::unordered_map<duckdb::idx_t, duckdb::LogicalGet *> &gets,
                           const duckdb::ColumnBinding &b, duckdb::idx_t &out_table_index, std::string &out_col,
                           bool &fatal) {
	fatal = false;
	auto it = gets.find(b.table_index);
	if (it == gets.end())
		return false; // not a base-table GET — ignore (charged elsewhere)
	duckdb::LogicalGet *get = it->second;
	// A GET with no catalog table (table function / replacement scan) is not a
	// constrained base table; its columns are never charged to a real table.
	if (!get->GetTable())
		return false;
	const auto &cids = get->GetColumnIds();
	if (b.column_index >= cids.size()) {
		fatal = true; // real table, out-of-range column index -> fail closed
		return false;
	}
	// A virtual column (rowid / row-identifier, used by UPDATE/DELETE to address
	// rows) is NOT a named base-column read — skip it (don't charge, don't fail
	// closed). Keyed on the STRUCTURAL virtual flag, not on resolution failure, so
	// this can never mask a real column we failed to resolve.
	if (cids[b.column_index].IsVirtualColumn())
		return false;
	if (!cids[b.column_index].HasPrimaryIndex()) {
		fatal = true; // real table, unresolvable column -> fail closed
		return false;
	}
	duckdb::idx_t primary = cids[b.column_index].GetPrimaryIndex();
	if (primary >= get->names.size()) {
		fatal = true;
		return false;
	}
	out_table_index = b.table_index;
	out_col = LowerCopy(get->names[primary]);
	return true;
}

// Build a BoundTableUse for a real base-table GET (identity from GetTable()).
inline BoundTableUse MakeBoundTableUse(duckdb::LogicalGet &get) {
	BoundTableUse u;
	auto tbl = get.GetTable();
	u.catalog = LowerCopy(tbl->ParentCatalog().GetName());
	u.schema = LowerCopy(tbl->ParentSchema().name);
	u.table = LowerCopy(tbl->name);
	u.ref = QualifyRef(u.catalog, u.schema, u.table);
	u.write = false;
	return u;
}

// Bind + walk ONE statement, folding its tables/columns into `out` (so a
// multi-statement batch accumulates). Returns false (and sets out.cls/reason) on
// a fail-closed condition (bind throws, forbidden operator, unresolvable column).
inline bool BindAnalyzeStatement(duckdb::ClientContext &ctx, duckdb::SQLStatement &stmt,
                                 std::unordered_map<std::string, BoundTableUse> &acc, std::string &reason) {
	using namespace duckdb;
	auto binder = Binder::CreateBinder(ctx);
	BoundStatement bound = binder->Bind(stmt);

	BoundAclVisitor v;
	v.VisitOperator(*bound.plan);
	if (v.forbidden) {
		reason = v.reason;
		return false;
	}

	// Pass 2: every base-table GET becomes a BoundTableUse (read), keyed by ref so
	// the same table scanned twice merges its column reads.
	auto touch = [&](const BoundTableUse &tu) -> BoundTableUse & {
		auto it = acc.find(tu.ref);
		if (it == acc.end())
			it = acc.emplace(tu.ref, tu).first;
		if (tu.write)
			it->second.write = true;
		for (auto &c : tu.read_cols) // merge written/read columns (write-target charges)
			it->second.read_cols.insert(c);
		return it->second;
	};
	std::unordered_map<idx_t, std::string> ti_to_ref; // table_index -> acc key
	for (auto &kv : v.gets) {
		LogicalGet *get = kv.second;
		if (!get->GetTable())
			continue; // table function / replacement scan — not a constrained table
		BoundTableUse tu = MakeBoundTableUse(*get);
		if (IsSystemRef(tu.catalog, tu.schema, tu.table))
			continue; // introspection (duckdb_*/pg_*/information_schema) — never gated
		touch(tu);
		ti_to_ref[kv.first] = tu.ref;
	}
	// write/DDL targets.
	for (auto &wt : v.write_tables)
		touch(wt);

	// Charge every resolved column read to its table_index's table.
	for (auto &b : v.bindings) {
		idx_t ti;
		std::string col;
		bool fatal = false;
		if (!ResolveBinding(v.gets, b, ti, col, fatal)) {
			if (fatal) {
				reason = "unresolved_column";
				return false; // fail closed
			}
			continue;
		}
		auto rit = ti_to_ref.find(ti);
		if (rit == ti_to_ref.end())
			continue; // system/introspection table_index, skipped above
		acc[rit->second].read_cols.insert(col);
	}
	return true;
}

// Top-level: parse, then bind+walk EVERY statement in the batch (Authorize-style:
// any forbidden/unbindable statement denies the whole batch). Produces a
// BoundAclAnalysis whose `tables` feed the existing grant check + the bound
// constraint enforcement. FAILS CLOSED on any exception.
//
// `lake_catalog` (from State::LakeCatalog()) is installed as the default catalog
// search path before binding so a bare `t` (form-A push-down on a transient
// connection where `USE lake` did not carry) resolves against the lake. The hook
// runs on the SHARED connection, so the search path is saved and RESTORED.
inline BoundAclAnalysis BindAnalyze(duckdb::ClientContext &ctx, const std::string &sql,
                                    const std::string &lake_catalog) {
	using namespace duckdb;
	BoundAclAnalysis a;

	Parser parser(ctx.GetParserOptions());
	try {
		parser.ParseQuery(sql);
	} catch (const std::exception &) {
		a.cls = AclClass::PARSE_ERR;
		a.reason = "parse_error";
		return a;
	}
	if (parser.statements.empty()) {
		a.cls = AclClass::ALLOW_ALL;
		return a;
	}

	// Save + set catalog search path to the lake (restored in all exit paths).
	bool path_saved = false;
	duckdb::vector<CatalogSearchEntry> saved_path;
	CatalogSearchPath *csp = nullptr;
	if (!lake_catalog.empty()) {
		try {
			csp = ClientData::Get(ctx).catalog_search_path.get();
			saved_path = csp->GetSetPaths();
			path_saved = true;
			duckdb::vector<CatalogSearchEntry> np;
			np.emplace_back(lake_catalog, "main");
			csp->Set(np, CatalogSetPathType::SET_SCHEMAS);
		} catch (const std::exception &) {
			// If we can't set the search path, proceed without it; a bare unqualified
			// ref may then fail to bind -> fail closed (deny), which is safe.
			csp = nullptr;
		}
	}

	std::unordered_map<std::string, BoundTableUse> acc;
	std::string reason;
	bool ok = true;
	try {
		for (auto &stmt : parser.statements) {
			if (!BindAnalyzeStatement(ctx, *stmt, acc, reason)) {
				ok = false;
				break;
			}
		}
	} catch (const std::exception &) {
		ok = false;
		reason = "bind_error";
	}

	// Restore search path no matter what.
	if (path_saved && csp) {
		try {
			csp->Set(saved_path, CatalogSetPathType::SET_SCHEMAS);
		} catch (...) {
		}
	}

	if (!ok) {
		a.cls = AclClass::FORBIDDEN; // fail closed (parse_err vs forbidden both deny)
		a.reason = reason.empty() ? "bind_error" : reason;
		return a;
	}

	for (auto &kv : acc)
		a.tables.push_back(std::move(kv.second));
	a.cls = a.tables.empty() ? AclClass::ALLOW_ALL : AclClass::CHECK;
	return a;
}

} // namespace birdshot
