#pragma once

// ACL analysis of a peer's SQL statement.
//
// Per-table ACLs need real table identity, so this uses DuckDB's own parser
// rather than regex. But a statement can do damage WITHOUT naming a base table —
// via functions (read_blob, query_table, or birdshot's own mutators) or wrapper
// statements (EXPLAIN ANALYZE). So Analyze flags three things:
//   * the (table, action) set a statement touches (per-table ACL), and
//   * dangerous FUNCTION calls           -> FORBIDDEN, and
//   * non-introspection TABLE functions  -> FORBIDDEN,
// and it descends into EXPLAIN's child so EXPLAIN ANALYSE can't execute unchecked.
//
// Threat model (see docs/internal/duckdb/birdshot/design.md + security audit):
//   - A peer must NEVER call birdshot_* (would let it wipe/rewrite policy, revoke
//     others, or — in HS256 — set the secret and forge tokens). All birdshot_*
//     are catalog-global scalar functions, callable from a zero-base-table SELECT.
//   - File/URL/dynamic readers (read_blob/read_csv/glob/query/query_table) read
//     arbitrary files/tables and can trigger httpfs autoload (SSRF/RCE-adjacent
//     under allow_unsigned_extensions). Denied.
//   - Table functions are deny-by-default; only duckdb_*/pragma_* introspection is
//     allowed, which is what quack's ATTACH handshake needs.
//
// The walkers FAIL CLOSED (Analyze catches any exception -> deny). Recursion depth
// is bounded by the parser's own nesting limit (deeply nested SQL is rejected at
// ParseQuery time, before we walk it).

#include <functional>
#include <string>
#include <vector>

#include "birdshot_state.hpp" // Capability, Covers(), ResourcePolicy, ParseCapability
#include "duckdb.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parsed_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/expression/window_expression.hpp"
#include "duckdb/parser/expression/cast_expression.hpp"
#include "duckdb/parser/expression/columnref_expression.hpp"
#include "duckdb/parser/expression/positional_reference_expression.hpp"
#include "duckdb/parser/expression/star_expression.hpp"
#include "duckdb/parser/query_node.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/query_node/set_operation_node.hpp"
#include "duckdb/parser/query_node/recursive_cte_node.hpp"
#include "duckdb/parser/query_node/cte_node.hpp"
#include "duckdb/parser/result_modifier.hpp"
#include "duckdb/parser/tableref.hpp"
#include "duckdb/parser/tableref/basetableref.hpp"
#include "duckdb/parser/tableref/joinref.hpp"
#include "duckdb/parser/tableref/subqueryref.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/parser/tableref/expressionlistref.hpp"
#include "duckdb/parser/tableref/pivotref.hpp"
#include "duckdb/parser/tableref/showref.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/statement/insert_statement.hpp"
#include "duckdb/parser/statement/update_statement.hpp"
#include "duckdb/parser/statement/delete_statement.hpp"
#include "duckdb/parser/statement/explain_statement.hpp"
// Full-scope ACL: every remaining statement class becomes a grantable capability,
// authorized HERE at the parse layer (not the bind-walk). The bind-walk's unknown-
// operator floor is default-ALLOW (it relies on this pre-filter to forbid every
// non-SELECT/DML class), and external-resource statements can't bind under the hook's
// enable_external_access=false anyway — so catalog DDL targets and external-resource
// literals are both pulled from the parse tree here, where no I/O occurs.
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/statement/drop_statement.hpp"
#include "duckdb/parser/statement/alter_statement.hpp"
#include "duckdb/parser/statement/copy_statement.hpp"
#include "duckdb/parser/statement/attach_statement.hpp"
#include "duckdb/parser/statement/detach_statement.hpp"
#include "duckdb/parser/statement/load_statement.hpp"
#include "duckdb/parser/parsed_data/create_table_info.hpp"
#include "duckdb/parser/parsed_data/create_view_info.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/common/types/value.hpp"
#include "duckdb/common/enums/catalog_type.hpp"

namespace birdshot {

enum class AclClass {
	CHECK,     // proceed to per-table ACL check using `tables`
	ALLOW_ALL, // benign/handshake statement(s); no table ACL (PRAGMA, tx, zero-table)
	FORBIDDEN, // statement / function class a peer may never run
	PARSE_ERR, // could not parse / extract -> fail closed
};

struct TableUse {
	std::string ref; // joined non-empty parts: "[catalog.][schema.]table", lowercased
	Capability cap = Capability::READ; // READ for SELECT, WRITE for INSERT/UPDATE/DELETE
	// Raw, separately-kept components (lowercased) for column attribution +
	// catalog positional resolution in Authorize. `catalog`/`schema` may be empty
	// (unqualified ref). `alias` is the FROM-clause alias if one was given, else
	// the table name — used to match qualified column refs to this table.
	std::string catalog;
	std::string schema;
	std::string table;
	std::string alias;
};

// A column referenced in the statement (lowercased). `qualifier` is the
// table/alias qualifier if the ref was qualified (e.g. `t.c1`), else empty.
// An unqualified ref (USING keys included) is resolved against each constrained
// table's catalog column set in the enforcement step (S8), so no special tag is
// needed to distinguish USING columns.
struct ColUse {
	std::string qualifier;
	std::string name;
};

// A non-catalog resource reference extracted from the parse tree (a read_source URI,
// a COPY destination, an ATTACH path, or an INSTALL/LOAD extension name), checked in
// Authorize against the caller's per-role policy lists. `literal` is ALWAYS a constant
// pinned from the statement — a non-constant resource is NEVER recorded here; the
// statement is forbidden instead. (An un-pinned resource under a serving connection
// with live egress would be an exfiltration / SSRF hole — the one place a mistake here
// is an ACL bypass, so "couldn't extract a constant" => deny, always.)
struct PolicyUse {
	Capability cap;      // READ_SOURCE | COPY_TO | ATTACH | INSTALL
	std::string literal; // verbatim URI / path / extension name (NOT lowercased)
};

// Threaded through the walkers: accumulates tables/columns and trips `forbidden`
// the moment a dangerous function / table function is seen. Column-level data is
// collected for ALL touched columns (select/where/having/qualify, recursively
// through subqueries/CTEs) so column enforcement sees the full read surface.
struct WalkCtx {
	std::vector<TableUse> tables;
	std::vector<ColUse> columns;        // named column refs (form B / lake.query)
	std::vector<int64_t> positions;     // 1-based positional refs (form A push-down)
	// One entry per non-fully-enumerated star (`*`, `t.*`, COLUMNS(...)): the
	// lowercased qualifier, empty for a bare star / COLUMNS(). A constrained table
	// is denied only by a bare star or a star qualified to its own alias.
	std::vector<std::string> star_quals;
	// Scope stack of in-scope declared CTE names (lowercased). Pushed on entry to a
	// node/statement that declares CTEs, popped on exit (by saved size), so an
	// unqualified base-table ref matching an in-scope CTE name is recognized as a
	// CTE self-reference (not a phantom ungranted table) — WITHOUT a flat global
	// set that would mask a real base table sharing a name in a sibling scope.
	std::vector<std::string> cte_scope;
	// Catalog-DDL capability uses (CREATE / DROP / ALTER / DETACH targets) carrying
	// their required Capability — authorized directly against grants (Covers) in
	// Authorize, NOT via the bind-walk. CTAS / COPY source reads are collected into
	// `tables` (above) by the same query-node walk, so both are checked together.
	std::vector<TableUse> cap_uses;
	// External-resource policy uses (see PolicyUse) — matched against the role's
	// source/dest/ext/attach allowlists in Authorize.
	std::vector<PolicyUse> policy_uses;
	bool forbidden = false;
	std::string reason;
};

struct AclAnalysis {
	AclClass cls = AclClass::PARSE_ERR;
	std::vector<TableUse> tables;
	// Column-level read surface, carried through for the constraint enforcement
	// step in Authorize (column allow-lists). Only meaningful when cls == CHECK.
	std::vector<ColUse> columns;
	std::vector<int64_t> positions;
	std::vector<std::string> star_quals;
	// Capability + policy uses for the full-scope (non-SELECT/DML) statement classes.
	// When EITHER is non-empty the batch took the parse-authorized path: Authorize
	// checks these (and `tables`, for any CTAS/COPY source reads) directly and does
	// NOT run the bind-walk.
	std::vector<TableUse> cap_uses;
	std::vector<PolicyUse> policy_uses;
	std::string reason;
};

inline std::string LowerCopy(std::string s) {
	for (auto &ch : s)
		ch = static_cast<char>(::tolower(static_cast<unsigned char>(ch)));
	return s;
}

inline bool IsSystemRef(const std::string &catalog, const std::string &schema, const std::string &table) {
	auto c = LowerCopy(catalog), s = LowerCopy(schema), t = LowerCopy(table);
	if (s == "information_schema" || s == "pg_catalog" || c == "system" || s == "system")
		return true;
	if (t.rfind("duckdb_", 0) == 0 || t.rfind("pragma_", 0) == 0 || s.rfind("pg_", 0) == 0)
		return true;
	return false;
}

inline std::string QualifyRef(const std::string &catalog, const std::string &schema, const std::string &table) {
	std::string out;
	if (!catalog.empty())
		out += catalog + ".";
	if (!schema.empty())
		out += schema + ".";
	out += table;
	return LowerCopy(out);
}

// A scalar/aggregate function a peer must never call.
inline bool IsDangerousScalarFunc(const std::string &lname) {
	if (lname.rfind("birdshot_", 0) == 0)
		return true; // birdshot's own mutators / config / revoke
	if (lname.rfind("read_", 0) == 0)
		return true; // read_blob/read_text/read_csv/read_json/read_parquet/...
	static const char *const kBad[] = {"query",         "query_table",     "glob",  "sniff_csv",
	                                   "parquet_scan",  "parquet_metadata", "parquet_schema",
	                                   "getvariable",   "read"};
	for (auto b : kBad)
		if (lname == b)
			return true;
	return false;
}

// Table-valued functions are deny-by-default; only introspection is allowed
// (quack's ATTACH handshake scans duckdb_tables()/pragma_* etc.). `whoami` is
// quack's documented node-identity macro returning only static metadata.
inline bool IsSafeTableFunc(const std::string &lname) {
	return lname.rfind("duckdb_", 0) == 0 || lname.rfind("pragma_", 0) == 0 || lname == "whoami";
}

// Table-valued functions that read an EXTERNAL source by URI/path. These are
// POLICY-GATED (Capability::READ_SOURCE) rather than hard-denied: the first constant
// string arg is the source URI, checked against the role's source_policies in
// Authorize. The scalar read_blob/read_text variants stay hard-denied by
// IsDangerousScalarFunc — only the FROM-clause table-function forms are gated here
// (that is the ETL surface: CTAS / SELECT over read_json_auto/read_csv_auto/...).
inline bool IsReadSourceTableFunc(const std::string &lname) {
	static const char *const kSrc[] = {
	    "read_json",       "read_json_auto", "read_ndjson", "read_ndjson_auto", "read_json_objects",
	    "read_csv",        "read_csv_auto",  "read_parquet", "parquet_scan",
	    "read_text",       "read_blob",      "glob",
	};
	for (auto s : kSrc)
		if (lname == s)
			return true;
	return false;
}

// Extract a non-null VARCHAR constant from a parse-tree expression. Returns true and
// sets `out` only for a literal string; a column ref / function / parameter / subquery
// returns false — the caller MUST then treat the resource as un-pinnable and FORBID
// the statement (never silently allow an un-extracted external resource).
inline bool ConstStringArg(const duckdb::ParsedExpression &expr, std::string &out) {
	using namespace duckdb;
	if (expr.GetExpressionClass() != ExpressionClass::CONSTANT)
		return false;
	auto &ce = expr.Cast<ConstantExpression>();
	if (ce.value.IsNull() || ce.value.type().id() != LogicalTypeId::VARCHAR)
		return false;
	out = StringValue::Get(ce.value);
	return true;
}

// CAST autoload protection lives at the BIND layer, not here: at PARSE time EVERY
// cast target (even core INTEGER/VARCHAR) is an UNKNOWN-id named placeholder, so a
// parse-time "unknown id => extension type" heuristic blocks ALL casts. Bind-and-walk
// binds the statement instead — a cast to a first-party extension type autoloads
// (trusted) and binds; a genuinely unknown type fails to bind => fail-closed deny.
// Build a ColUse (small helper to keep collection sites uniform).
inline ColUse MakeCol(const std::string &qualifier, const std::string &name) {
	ColUse c;
	c.qualifier = qualifier;
	c.name = name;
	return c;
}

// ---- tree walk (const, ctx-threaded) ---------------------------------------

inline void WalkNode(const duckdb::QueryNode &node, WalkCtx &ctx);
inline void WalkRefAsWrite(const duckdb::TableRef &ref, WalkCtx &ctx);

inline void WalkExpr(const duckdb::ParsedExpression &expr, WalkCtx &ctx) {
	using namespace duckdb;
	auto cls = expr.GetExpressionClass();
	if (cls == ExpressionClass::FUNCTION) {
		auto &fe = expr.Cast<FunctionExpression>();
		if (IsDangerousScalarFunc(LowerCopy(fe.function_name))) {
			ctx.forbidden = true;
			ctx.reason = "forbidden_func:" + LowerCopy(fe.function_name);
		}
	} else if (cls == ExpressionClass::WINDOW) {
		// A dangerous function used as a window function (OVER (...)) — same denylist.
		auto &we = expr.Cast<WindowExpression>();
		if (IsDangerousScalarFunc(LowerCopy(we.function_name))) {
			ctx.forbidden = true;
			ctx.reason = "forbidden_winfunc:" + LowerCopy(we.function_name);
		}
	} else if (cls == ExpressionClass::SUBQUERY) {
		auto &sub = expr.Cast<SubqueryExpression>();
		if (sub.subquery && sub.subquery->node)
			WalkNode(*sub.subquery->node, ctx);
	} else if (cls == ExpressionClass::COLUMN_REF) {
		// A named column reference (form B / lake.query, or any qualified ref).
		auto &cr = expr.Cast<ColumnRefExpression>();
		ColUse cu;
		cu.name = LowerCopy(cr.GetColumnName());
		if (cr.IsQualified())
			cu.qualifier = LowerCopy(cr.GetTableName());
		ctx.columns.push_back(cu);
	} else if (cls == ExpressionClass::POSITIONAL_REFERENCE) {
		// `#N` (1-based catalog ordinal) — quack's form-A push-down representation.
		auto &pr = expr.Cast<PositionalReferenceExpression>();
		ctx.positions.push_back(static_cast<int64_t>(pr.index));
	} else if (cls == ExpressionClass::STAR) {
		// ANY non-fully-enumerated star is unenumerable against a column allow-list:
		// bare `*`, qualified `t.*` (relation_name set), and COLUMNS(*)/COLUMNS('re')
		// (se.columns == true; treated as a bare star). Record its qualifier so the
		// enforcement step denies only the table the star could actually read: a
		// bare star (empty qualifier) denies every constrained table, a `t.*` denies
		// only the table aliased `t`. (Form A never sends a literal star — quack
		// pre-expands to positions — so this only scopes the form-B parser walk.)
		auto &se = expr.Cast<StarExpression>();
		ctx.star_quals.push_back(se.columns ? std::string() : LowerCopy(se.relation_name));
	}
	ParsedExpressionIterator::EnumerateChildren(expr, [&](const ParsedExpression &child) { WalkExpr(child, ctx); });
}

// Build a TableUse from a base-table ref, carrying both the joined ref (for grant
// matching) and the raw lowercased components + alias (for column attribution and
// catalog positional resolution). The alias defaults to the table name.
inline TableUse MakeBaseUse(const duckdb::BaseTableRef &bt, Capability cap) {
	TableUse u;
	u.ref = QualifyRef(bt.catalog_name, bt.schema_name, bt.table_name);
	u.cap = cap;
	u.catalog = LowerCopy(bt.catalog_name);
	u.schema = LowerCopy(bt.schema_name);
	u.table = LowerCopy(bt.table_name);
	u.alias = bt.alias.empty() ? LowerCopy(bt.table_name) : LowerCopy(bt.alias);
	return u;
}

inline void WalkRef(const duckdb::TableRef &ref, WalkCtx &ctx) {
	using namespace duckdb;
	switch (ref.type) {
	case TableReferenceType::BASE_TABLE: {
		auto &bt = ref.Cast<BaseTableRef>();
		// An unqualified ref (no catalog/schema) matching an in-scope CTE name is a
		// CTE self-reference, not a base table — don't charge it as a phantom
		// ungranted table. (The CTE body is walked separately via the cte_map loop,
		// so its real reads stay charged.) A QUALIFIED ref can't be a CTE ref.
		if (bt.catalog_name.empty() && bt.schema_name.empty()) {
			std::string lname = LowerCopy(bt.table_name);
			for (const auto &cte : ctx.cte_scope)
				if (cte == lname)
					return; // recognized CTE name in scope -> not a base table
		}
		if (!IsSystemRef(bt.catalog_name, bt.schema_name, bt.table_name))
			ctx.tables.push_back(MakeBaseUse(bt, Capability::READ));
		break;
	}
	case TableReferenceType::JOIN: {
		auto &j = ref.Cast<JoinRef>();
		if (j.left)
			WalkRef(*j.left, ctx);
		if (j.right)
			WalkRef(*j.right, ctx);
		// ON predicate columns are touched columns.
		if (j.condition)
			WalkExpr(*j.condition, ctx);
		// USING(col,...) columns are present on BOTH sides. Collected as plain
		// unqualified column refs; S8's catalog resolution checks them against each
		// constrained table's column set (they resolve onto both sides), so no
		// special tagging is needed.
		for (auto &uc : j.using_columns)
			ctx.columns.push_back(MakeCol(std::string(), LowerCopy(uc)));
		// NATURAL (and DEPENDENT) join keys are bind-time common columns — invisible
		// to the parser (no condition, no using_columns). Fail closed: record a bare
		// unenumerable star so a column-constrained side is denied (its forbidden
		// common columns could be read as join keys). CROSS/POSITIONAL have no column
		// keys; REGULAR/ASOF carry a real ON already walked above.
		if (j.ref_type == JoinRefType::NATURAL || j.ref_type == JoinRefType::DEPENDENT)
			ctx.star_quals.push_back(std::string());
		break;
	}
	case TableReferenceType::SUBQUERY: {
		auto &sq = ref.Cast<SubqueryRef>();
		if (sq.subquery && sq.subquery->node)
			WalkNode(*sq.subquery->node, ctx);
		break;
	}
	case TableReferenceType::TABLE_FUNCTION: {
		auto &tf = ref.Cast<TableFunctionRef>();
		const FunctionExpression *fexpr = nullptr;
		std::string fn;
		if (tf.function && tf.function->GetExpressionClass() == ExpressionClass::FUNCTION) {
			fexpr = &tf.function->Cast<FunctionExpression>();
			fn = LowerCopy(fexpr->function_name);
		}
		if (fexpr && IsReadSourceTableFunc(fn)) {
			// Policy-gated external read. Pin the source to the FIRST constant string
			// arg; a non-constant source can't be policy-checked under live egress, so
			// fail closed (deny the statement) rather than allow an un-pinned source.
			std::string uri;
			if (!fexpr->children.empty() && ConstStringArg(*fexpr->children[0], uri)) {
				PolicyUse pu;
				pu.cap = Capability::READ_SOURCE;
				pu.literal = uri;
				ctx.policy_uses.push_back(pu);
				// Walk only the REMAINING args for nested danger (a subquery / dangerous
				// scalar hidden in a later arg). Skip child[0] (the constant URI) and the
				// function node itself — its read_* name would otherwise re-trip the
				// IsDangerousScalarFunc denylist and forbid this now-allowed read source.
				for (size_t k = 1; k < fexpr->children.size(); k++)
					if (fexpr->children[k])
						WalkExpr(*fexpr->children[k], ctx);
			} else {
				ctx.forbidden = true;
				ctx.reason = "read_source_nonconst:" + fn;
			}
			if (tf.subquery && tf.subquery->node)
				WalkNode(*tf.subquery->node, ctx);
			break;
		}
		if (fn.empty() || !IsSafeTableFunc(fn)) {
			ctx.forbidden = true;
			ctx.reason = "forbidden_tablefunc:" + fn;
		}
		// Even inside an allowed introspection fn, the ARGS can carry a dangerous
		// scalar / autoload CAST / subquery reading a base table — walk them so the
		// expr-level denylist re-applies. (Literal-string / no-arg introspection used
		// by the ATTACH handshake collects nothing here and stays allowed.)
		if (tf.function)
			WalkExpr(*tf.function, ctx);
		if (tf.subquery && tf.subquery->node)
			WalkNode(*tf.subquery->node, ctx);
		break;
	}
	case TableReferenceType::EXPRESSION_LIST: {
		// VALUES (...). Each cell is an expression that can hide a scalar subquery
		// reading a base table — walk them all.
		auto &el = ref.Cast<ExpressionListRef>();
		for (auto &row : el.values)
			for (auto &cell : row)
				if (cell)
					WalkExpr(*cell, ctx);
		break;
	}
	case TableReferenceType::PIVOT: {
		// PIVOT / UNPIVOT. The pivoted source is a real table read; aggregates and
		// pivot expressions reference columns.
		auto &p = ref.Cast<PivotRef>();
		if (p.source)
			WalkRef(*p.source, ctx);
		for (auto &agg : p.aggregates)
			if (agg)
				WalkExpr(*agg, ctx);
		for (auto &pc : p.pivots) {
			for (auto &e : pc.pivot_expressions)
				if (e)
					WalkExpr(*e, ctx);
			// `IN (...)` value list: a subquery here reads a base table. Walk the
			// transform-time subquery unconditionally; walk an entry expr ONLY when
			// it actually contains a subquery (plain `IN (foo, bar)` labels parse as
			// column refs and would otherwise over-deny a legitimate PIVOT).
			if (pc.subquery)
				WalkNode(*pc.subquery, ctx);
			for (auto &e : pc.entries)
				if (e.expr && e.expr->HasSubquery())
					WalkExpr(*e.expr, ctx);
		}
		break;
	}
	case TableReferenceType::SHOW_REF: {
		// SHOW / DESCRIBE / SUMMARIZE. DuckDB transforms a DESCRIBE/SUMMARIZE of a
		// SPECIFIC relation into a ShowRef carrying a `query` = `SELECT * FROM
		// <rel>` (table_name stays empty); the bare introspection forms (`SHOW
		// tables`, `SHOW ALL TABLES`, `SHOW TABLES FROM db`) carry only
		// table_name/schema_name with NO query.
		//
		// A DESCRIBE/SUMMARIZE of a relation leaks that relation's existence +
		// column names but DESCRIBE produces NO scan, so bind-and-walk (which only
		// sees LogicalGet scans) is blind to it -> it would fall through to
		// ALLOW_ALL. Fail closed at the parse layer whenever a `query` is present
		// (it names a specific relation) — this denies DESCRIBE/SUMMARIZE of any
		// table, including a granted-but-column-constrained one whose constrained
		// column names DESCRIBE would otherwise expose. The bare table_name-only
		// SHOW forms (the ATTACH handshake needs them) stay allowed.
		auto &sr = ref.Cast<ShowRef>();
		if (sr.query) {
			ctx.forbidden = true;
			ctx.reason = "forbidden_describe";
			WalkNode(*sr.query, ctx); // defense in depth: still gate the inner query
		}
		break;
	}
	case TableReferenceType::EMPTY_FROM:
		// No FROM (`SELECT 1`, handshake/introspection scalars): no catalog table.
		break;
	default:
		// FAIL CLOSED: an unrecognized tableref we don't traverse could read a base
		// table we never see -> default-allow bypass. Deny the whole statement.
		ctx.forbidden = true;
		ctx.reason = "unhandled_tableref";
		break;
	}
}

inline void WalkNode(const duckdb::QueryNode &node, WalkCtx &ctx) {
	using namespace duckdb;
	size_t cte_mark = ctx.cte_scope.size();
	// Walk each CTE body FIRST, bringing its name into scope only AFTER its own body
	// is walked. A non-recursive CTE body cannot reference itself, so its body must
	// see preceding siblings but NOT its own name — otherwise the body's real
	// base-table read (e.g. `WITH t AS (SELECT c3 FROM t)`) would be wrongly
	// suppressed as a self-reference, dropping it from enforcement. Declaration
	// order is guaranteed by cte_map's InsertionOrderPreservingMap, so "preceding
	// siblings" is well-defined. (The recursive self-ref is handled separately in
	// the RECURSIVE_CTE_NODE case, which pushes its own name before walking.)
	for (auto &kv : node.cte_map.map) {
		if (kv.second && kv.second->query && kv.second->query->node)
			WalkNode(*kv.second->query->node, ctx);
		ctx.cte_scope.push_back(LowerCopy(kv.first));
	}
	// The main query body now runs with ALL of this node's CTE names in scope, so a
	// main-query `FROM cte` ref is recognized as a CTE (not charged as a phantom).
	switch (node.type) {
	case QueryNodeType::SELECT_NODE: {
		auto &sel = node.Cast<SelectNode>();
		if (sel.from_table)
			WalkRef(*sel.from_table, ctx);
		for (auto &e : sel.select_list)
			if (e)
				WalkExpr(*e, ctx);
		if (sel.where_clause)
			WalkExpr(*sel.where_clause, ctx);
		if (sel.having)
			WalkExpr(*sel.having, ctx);
		if (sel.qualify)
			WalkExpr(*sel.qualify, ctx);
		// GROUP BY columns count as touched (a column read for grouping).
		for (auto &g : sel.groups.group_expressions)
			if (g)
				WalkExpr(*g, ctx);
		break;
	}
	case QueryNodeType::SET_OPERATION_NODE: {
		auto &so = node.Cast<SetOperationNode>();
		for (auto &child : so.children)
			if (child)
				WalkNode(*child, ctx);
		break;
	}
	case QueryNodeType::RECURSIVE_CTE_NODE: {
		// WITH RECURSIVE: the real table reads live in left/right, which the
		// cte_map loop below does NOT reach. The node's own name is in scope so the
		// recursive self-reference (`... UNION SELECT ... FROM <ctename>`) isn't
		// charged as a phantom table.
		auto &r = node.Cast<RecursiveCTENode>();
		ctx.cte_scope.push_back(LowerCopy(r.ctename));
		if (r.left)
			WalkNode(*r.left, ctx);
		if (r.right)
			WalkNode(*r.right, ctx);
		for (auto &kt : r.key_targets)
			if (kt)
				WalkExpr(*kt, ctx);
		break;
	}
	case QueryNodeType::CTE_NODE: {
		// A materialized-CTE node carries both the CTE body (`query`) and the main
		// query (`child`). Walk both (idempotent; covers whichever shape v1.5.3 emits).
		auto &c = node.Cast<CTENode>();
		for (auto &a : c.aliases)
			ctx.cte_scope.push_back(LowerCopy(a));
		if (c.query)
			WalkNode(*c.query, ctx);
		if (c.child)
			WalkNode(*c.child, ctx);
		break;
	}
	default:
		// FAIL CLOSED on an unrecognized query node — an un-walked node could read a
		// base table we never charge -> default-allow bypass.
		ctx.forbidden = true;
		ctx.reason = "unhandled_querynode";
		break;
	}
	// Result modifiers (ORDER BY, DISTINCT ON, LIMIT/OFFSET exprs) live on the base
	// QueryNode and also reference columns — collect them so column enforcement sees
	// the full read surface on the verbatim (form-B) path. (LIMIT here is column-ref
	// collection only — NOT row-cap logic, which birdshot does not do.)
	for (auto &mod : node.modifiers) {
		if (!mod)
			continue;
		if (mod->type == ResultModifierType::ORDER_MODIFIER) {
			auto &om = mod->Cast<OrderModifier>();
			for (auto &o : om.orders)
				if (o.expression)
					WalkExpr(*o.expression, ctx);
		} else if (mod->type == ResultModifierType::DISTINCT_MODIFIER) {
			auto &dm = mod->Cast<DistinctModifier>();
			for (auto &t : dm.distinct_on_targets)
				if (t)
					WalkExpr(*t, ctx);
		} else if (mod->type == ResultModifierType::LIMIT_MODIFIER) {
			auto &lm = mod->Cast<LimitModifier>();
			if (lm.limit)
				WalkExpr(*lm.limit, ctx);
			if (lm.offset)
				WalkExpr(*lm.offset, ctx);
		} else if (mod->type == ResultModifierType::LIMIT_PERCENT_MODIFIER) {
			auto &lpm = mod->Cast<LimitPercentModifier>();
			if (lpm.limit)
				WalkExpr(*lpm.limit, ctx);
			if (lpm.offset)
				WalkExpr(*lpm.offset, ctx);
		}
	}
	// Pop every CTE name brought into scope by this node (and its CTE-node cases).
	// (CTE bodies were already walked up front, with correct preceding-sibling scope.)
	ctx.cte_scope.resize(cte_mark);
}

inline void WalkRefAsWrite(const duckdb::TableRef &ref, WalkCtx &ctx) {
	using namespace duckdb;
	if (ref.type == TableReferenceType::BASE_TABLE) {
		auto &bt = ref.Cast<BaseTableRef>();
		if (!IsSystemRef(bt.catalog_name, bt.schema_name, bt.table_name))
			ctx.tables.push_back(MakeBaseUse(bt, Capability::WRITE));
	} else {
		WalkRef(ref, ctx);
	}
}

// ---- per-statement analysis ------------------------------------------------

// Walk a statement-level WITH clause's CTE bodies and bring their names into scope
// (DML reuses the same CommonTableExpressionMap shape as a query node). Each body
// is walked BEFORE its own name is pushed, so a body sees preceding siblings but
// not itself (same non-recursive-self-reference rule as WalkNode). Returns the
// prior stack size so the caller can pop with ctx.cte_scope.resize(mark) after the
// DML clauses (which run with all CTE names in scope) are walked.
inline size_t WalkDmlCtes(const duckdb::CommonTableExpressionMap &cte_map, WalkCtx &ctx) {
	size_t mark = ctx.cte_scope.size();
	for (auto &kv : cte_map.map) {
		if (kv.second && kv.second->query && kv.second->query->node)
			WalkNode(*kv.second->query->node, ctx);
		ctx.cte_scope.push_back(LowerCopy(kv.first));
	}
	return mark;
}

// Walk an UpdateSetInfo (shared by UPDATE and INSERT ... ON CONFLICT DO UPDATE):
// the SET predicate, the assigned expressions, and the assigned column names.
inline void WalkSetInfo(const duckdb::UpdateSetInfo &si, WalkCtx &ctx) {
	if (si.condition)
		WalkExpr(*si.condition, ctx);
	for (auto &e : si.expressions)
		if (e)
			WalkExpr(*e, ctx);
	for (auto &col : si.columns)
		ctx.columns.push_back(MakeCol(std::string(), LowerCopy(col)));
}

// Build a catalog-DDL capability use (CREATE/DROP/ALTER/DETACH target). `catalog`
// and `schema` may be empty (unqualified DDL); the ref omits empty components so it
// matches grants the same way a SELECT/DML ref does (via RefMatch).
inline TableUse MakeCapUse(const std::string &catalog, const std::string &schema, const std::string &name,
                           Capability cap) {
	TableUse u;
	u.catalog = LowerCopy(catalog);
	u.schema = LowerCopy(schema);
	u.table = LowerCopy(name);
	u.ref = QualifyRef(catalog, schema, name);
	u.alias = u.table;
	u.cap = cap;
	return u;
}

// Sets ctx.forbidden for a forbidden statement class; walks tables/functions for
// the DML it can. Returns false if the statement type is forbidden.
inline bool AnalyzeStatement(const duckdb::SQLStatement &stmt, WalkCtx &ctx) {
	using namespace duckdb;
	switch (stmt.type) {
	case StatementType::SELECT_STATEMENT: {
		auto &s = stmt.Cast<SelectStatement>();
		if (s.node)
			WalkNode(*s.node, ctx);
		return true;
	}
	case StatementType::INSERT_STATEMENT: {
		auto &s = stmt.Cast<InsertStatement>();
		size_t cte_mark = WalkDmlCtes(s.cte_map, ctx);
		if (!IsSystemRef(s.catalog, s.schema, s.table)) {
			TableUse u;
			u.ref = QualifyRef(s.catalog, s.schema, s.table);
			u.cap = Capability::WRITE;
			u.catalog = LowerCopy(s.catalog);
			u.schema = LowerCopy(s.schema);
			u.table = LowerCopy(s.table);
			u.alias = LowerCopy(s.table);
			ctx.tables.push_back(u);
		}
		// Explicit insert column list is a write surface.
		for (auto &col : s.columns)
			ctx.columns.push_back(MakeCol(std::string(), LowerCopy(col)));
		if (s.select_statement && s.select_statement->node)
			WalkNode(*s.select_statement->node, ctx);
		// ON CONFLICT DO UPDATE: its condition + SET clause read/write columns.
		if (s.on_conflict_info) {
			if (s.on_conflict_info->condition)
				WalkExpr(*s.on_conflict_info->condition, ctx);
			if (s.on_conflict_info->set_info)
				WalkSetInfo(*s.on_conflict_info->set_info, ctx);
		}
		for (auto &r : s.returning_list)
			if (r)
				WalkExpr(*r, ctx);
		ctx.cte_scope.resize(cte_mark);
		return true;
	}
	case StatementType::UPDATE_STATEMENT: {
		auto &s = stmt.Cast<UpdateStatement>();
		size_t cte_mark = WalkDmlCtes(s.cte_map, ctx);
		if (s.table)
			WalkRefAsWrite(*s.table, ctx);
		if (s.from_table)
			WalkRef(*s.from_table, ctx);
		if (s.set_info)
			WalkSetInfo(*s.set_info, ctx);
		for (auto &r : s.returning_list)
			if (r)
				WalkExpr(*r, ctx);
		ctx.cte_scope.resize(cte_mark);
		return true;
	}
	case StatementType::DELETE_STATEMENT: {
		auto &s = stmt.Cast<DeleteStatement>();
		size_t cte_mark = WalkDmlCtes(s.cte_map, ctx);
		if (s.table)
			WalkRefAsWrite(*s.table, ctx);
		for (auto &u : s.using_clauses)
			if (u)
				WalkRef(*u, ctx);
		if (s.condition)
			WalkExpr(*s.condition, ctx);
		for (auto &r : s.returning_list)
			if (r)
				WalkExpr(*r, ctx);
		ctx.cte_scope.resize(cte_mark);
		return true;
	}
	case StatementType::EXPLAIN_STATEMENT: {
		// EXPLAIN ANALYZE *executes* its child — descend and check it, don't wave through.
		auto &s = stmt.Cast<ExplainStatement>();
		if (s.stmt)
			return AnalyzeStatement(*s.stmt, ctx);
		return true;
	}
	case StatementType::TRANSACTION_STATEMENT:
		// BEGIN/COMMIT/ROLLBACK — needed for forwarded transactions. No tables.
		return true;

	// ---- Full-scope capability classes (authorized at the parse layer) ----------

	case StatementType::CREATE_STATEMENT: {
		auto &s = stmt.Cast<CreateStatement>();
		if (!s.info) {
			ctx.forbidden = true;
			ctx.reason = "create_no_info";
			return false;
		}
		CreateInfo &ci = *s.info;
		if (ci.type == CatalogType::TABLE_ENTRY) {
			auto &ti = ci.Cast<CreateTableInfo>();
			ctx.cap_uses.push_back(MakeCapUse(ci.catalog, ci.schema, ti.table, Capability::CREATE));
			// CTAS: the inner SELECT's source tables become READ uses (and any
			// read_source becomes a policy use) via the normal query-node walk.
			if (ti.query && ti.query->node)
				WalkNode(*ti.query->node, ctx);
			return true;
		}
		if (ci.type == CatalogType::VIEW_ENTRY) {
			auto &vi = ci.Cast<CreateViewInfo>();
			ctx.cap_uses.push_back(MakeCapUse(ci.catalog, ci.schema, vi.view_name, Capability::CREATE));
			// A view's SELECT body reads its source tables — charge them as READ uses
			// (and any read_source as a policy use) via the normal query-node walk.
			if (vi.query && vi.query->node)
				WalkNode(*vi.query->node, ctx);
			return true;
		}
		if (ci.type == CatalogType::SCHEMA_ENTRY) {
			// CREATE SCHEMA: the schema itself is the target (ci.schema holds its name).
			ctx.cap_uses.push_back(MakeCapUse(ci.catalog, std::string(), ci.schema, Capability::CREATE));
			return true;
		}
		// INDEX / SEQUENCE / TYPE / MACRO: the resource model for these (index → its
		// table? sequence → its own name?) is deferred to the Phase-3 capability
		// surfacing — fail closed for now (deny-safe; DROP/ALTER of them are already
		// generic via DropInfo/AlterInfo catalog.schema.name).
		ctx.forbidden = true;
		ctx.reason = "forbidden_create_type";
		return false;
	}
	case StatementType::DROP_STATEMENT: {
		auto &s = stmt.Cast<DropStatement>();
		if (!s.info) {
			ctx.forbidden = true;
			ctx.reason = "drop_no_info";
			return false;
		}
		DropInfo &di = *s.info;
		if (IsSystemRef(di.catalog, di.schema, di.name)) {
			ctx.forbidden = true;
			ctx.reason = "forbidden_drop_system";
			return false;
		}
		ctx.cap_uses.push_back(MakeCapUse(di.catalog, di.schema, di.name, Capability::DROP));
		return true;
	}
	case StatementType::ALTER_STATEMENT: {
		auto &s = stmt.Cast<AlterStatement>();
		if (!s.info) {
			ctx.forbidden = true;
			ctx.reason = "alter_no_info";
			return false;
		}
		AlterInfo &ai = *s.info;
		if (IsSystemRef(ai.catalog, ai.schema, ai.name)) {
			ctx.forbidden = true;
			ctx.reason = "forbidden_alter_system";
			return false;
		}
		ctx.cap_uses.push_back(MakeCapUse(ai.catalog, ai.schema, ai.name, Capability::ALTER));
		return true;
	}
	case StatementType::COPY_STATEMENT: {
		auto &s = stmt.Cast<CopyStatement>();
		if (!s.info) {
			ctx.forbidden = true;
			ctx.reason = "copy_no_info";
			return false;
		}
		CopyInfo &ci = *s.info;
		// The file path MUST be a literal. An expression-valued path (file_path_expression
		// set, file_path empty) can't be policy-pinned -> deny.
		if (ci.file_path.empty()) {
			ctx.forbidden = true;
			ctx.reason = "copy_nonconst_path";
			return false;
		}
		if (ci.is_from) {
			// COPY <table> FROM '<src>': read external source -> write target table.
			PolicyUse pu;
			pu.cap = Capability::READ_SOURCE;
			pu.literal = ci.file_path;
			ctx.policy_uses.push_back(pu);
			if (!ci.table.empty() && !IsSystemRef(ci.catalog, ci.schema, ci.table))
				ctx.cap_uses.push_back(MakeCapUse(ci.catalog, ci.schema, ci.table, Capability::WRITE));
		} else {
			// COPY (<query> | <table>) TO '<dest>': read source -> write external dest.
			PolicyUse pu;
			pu.cap = Capability::COPY_TO;
			pu.literal = ci.file_path;
			ctx.policy_uses.push_back(pu);
			if (ci.select_statement)
				WalkNode(*ci.select_statement, ctx); // COPY (SELECT ...) TO — source reads
			else if (!ci.table.empty() && !IsSystemRef(ci.catalog, ci.schema, ci.table))
				ctx.tables.push_back(MakeCapUse(ci.catalog, ci.schema, ci.table, Capability::READ));
		}
		return true;
	}
	case StatementType::ATTACH_STATEMENT: {
		auto &s = stmt.Cast<AttachStatement>();
		if (!s.info || s.info->path.empty()) {
			ctx.forbidden = true;
			ctx.reason = "attach_no_path";
			return false;
		}
		PolicyUse pu;
		pu.cap = Capability::ATTACH;
		pu.literal = s.info->path;
		ctx.policy_uses.push_back(pu);
		return true;
	}
	case StatementType::DETACH_STATEMENT: {
		auto &s = stmt.Cast<DetachStatement>();
		if (!s.info) {
			ctx.forbidden = true;
			ctx.reason = "detach_no_info";
			return false;
		}
		// DETACH targets a catalog ALIAS (no external resource); gate it as the DETACH
		// capability on that alias name (default-deny until a detach grant is emitted).
		ctx.cap_uses.push_back(MakeCapUse(std::string(), std::string(), s.info->name, Capability::DETACH));
		return true;
	}
	case StatementType::LOAD_STATEMENT: {
		auto &s = stmt.Cast<LoadStatement>();
		if (!s.info || s.info->filename.empty()) {
			ctx.forbidden = true;
			ctx.reason = "load_no_name";
			return false;
		}
		// INSTALL / LOAD / FORCE_INSTALL — the extension name (or path) is policy-gated.
		PolicyUse pu;
		pu.cap = Capability::INSTALL;
		pu.literal = s.info->filename;
		ctx.policy_uses.push_back(pu);
		return true;
	}

	default:
		// PRAGMA (reparses into engine statements that skip re-authorize; some pragmas
		// reach settings/file-write primitives), SET/RESET/VARIABLE_SET, CALL, EXPORT/
		// IMPORT, and any class not handled above stay deny-by-default (fail closed).
		ctx.forbidden = true;
		ctx.reason = "forbidden_stmt";
		return false;
	}
}

inline AclAnalysis Analyze(const std::string &sql) {
	using namespace duckdb;
	AclAnalysis a;
	Parser parser;
	try {
		parser.ParseQuery(sql);
	} catch (...) {
		a.cls = AclClass::PARSE_ERR;
		a.reason = "parse_error";
		return a;
	}
	if (parser.statements.empty()) {
		a.cls = AclClass::ALLOW_ALL;
		return a;
	}

	WalkCtx ctx;
	try {
		// Examine EVERY statement; any forbidden one denies the whole batch
		// (so `BEGIN; DROP TABLE t` can't smuggle the DROP past a benign first stmt).
		for (auto &stmt : parser.statements) {
			AnalyzeStatement(*stmt, ctx);
			if (ctx.forbidden) {
				a.cls = AclClass::FORBIDDEN;
				a.reason = ctx.reason;
				return a;
			}
		}
	} catch (...) {
		a.cls = AclClass::PARSE_ERR;
		a.reason = "extract_error";
		return a;
	}

	a.tables = std::move(ctx.tables);
	a.columns = std::move(ctx.columns);
	a.positions = std::move(ctx.positions);
	a.star_quals = std::move(ctx.star_quals);
	a.cap_uses = std::move(ctx.cap_uses);
	a.policy_uses = std::move(ctx.policy_uses);
	// ALLOW_ALL only when there is genuinely nothing to check — no catalog tables AND
	// no DDL capability uses AND no external-resource policy uses. A bare DROP / ATTACH
	// (empty `tables` but non-empty cap/policy uses) must be CHECK, never waved through.
	a.cls = (a.tables.empty() && a.cap_uses.empty() && a.policy_uses.empty()) ? AclClass::ALLOW_ALL
	                                                                          : AclClass::CHECK;
	return a;
}

// ---- Non-catalog resource policy matchers ----------------------------------
//
// These functions match a resource literal (extracted from the parse tree) against
// a role's ResourcePolicy list. They are called from Authorize's parse-authorized
// path: a read_source / copy_to / attach / install statement records a PolicyUse with
// the pinned constant literal, which is matched here against the caller's merged
// per-role policy list (source/dest/attach/ext).
//
// All matchers share the same default-deny contract:
//   empty policy list  =>  false (deny)
//   non-empty list     =>  true iff at least one entry matches the resource literal
//
// Security invariants:
//   - URI matchers require https:// or quack:// scheme; file:// and bare paths are
//     denied unless an explicit "file://<path>" entry exists in the policy list.
//   - Host matching uses exact-or-subdomain boundary (the RefMatch leading-dot
//     guard model): "example.com" matches "example.com" and "sub.example.com" but
//     NOT "notexample.com" or "evil.com/example.com".
//   - A bare "*" entry in the URI/Attach/Ext list is a wildcard (full allow).
//     Trailing ".*" on a host suffix allows all subdomains of that host.

// Return the scheme portion of a URI (e.g. "https" for "https://..."), lowercased.
// Returns "" if no "://" separator is present (bare path / no scheme).
inline std::string UriScheme(const std::string &uri) {
	size_t p = uri.find("://");
	if (p == std::string::npos)
		return "";
	std::string scheme = uri.substr(0, p);
	for (auto &ch : scheme)
		ch = static_cast<char>(::tolower(static_cast<unsigned char>(ch)));
	return scheme;
}

// Return the host portion of a URI (after "://", up to first "/" "?" "#" or end).
// Lowercased. Returns "" on malformed input or no "://" separator.
inline std::string UriHost(const std::string &uri) {
	size_t p = uri.find("://");
	if (p == std::string::npos)
		return "";
	size_t host_start = p + 3;
	size_t host_end = uri.find_first_of("/?#", host_start);
	if (host_end == std::string::npos)
		host_end = uri.size();
	std::string host = uri.substr(host_start, host_end - host_start);
	for (auto &ch : host)
		ch = static_cast<char>(::tolower(static_cast<unsigned char>(ch)));
	return host;
}

// True iff `host` matches `pattern` on an exact-or-dot-boundary basis.
// "example.com"  pattern matches "example.com" (exact) and "sub.example.com"
//                (pattern prepended with '.') but NOT "notexample.com".
// "*.example.com" pattern matches any subdomain of "example.com" (not bare host).
// "*" pattern matches any host.
inline bool HostMatch(const std::string &pattern, const std::string &host) {
	if (pattern == "*")
		return true;
	// Wildcard subdomain: "*.example.com" matches "a.example.com" but not "example.com".
	if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
		std::string suffix = pattern.substr(1); // ".example.com"
		// host must end with ".example.com" (i.e. is a proper subdomain).
		if (host.size() > suffix.size() &&
		    host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0)
			return true;
		return false;
	}
	// Exact match.
	if (pattern == host)
		return true;
	// Subdomain: pattern without wildcard allows itself AND any subdomain.
	// "example.com" matches "sub.example.com": host ends with "." + pattern.
	if (host.size() > pattern.size() + 1 &&
	    host[host.size() - pattern.size() - 1] == '.' &&
	    host.compare(host.size() - pattern.size(), pattern.size(), pattern) == 0)
		return true;
	return false;
}

// Match a source/destination URI against a policy list.
// Allowed schemes: "https" and "quack". All other schemes (including bare paths,
// "file://", "http://") are denied unless the policy list has an explicit entry
// for the full URI including that scheme.
//
// Policy entry matching rules (checked in order):
//   "*"             — allow any URI (full wildcard; use only in dev/trusted roles)
//   exact string    — the URI must equal the pattern exactly (including scheme+path)
//   "<host>"        — match any https:// or quack:// URI on the given host (exact or subdom)
//   "*.example.com" — match any https:// or quack:// URI on any subdomain of example.com
//
// Default scheme allowlist (https/quack) is applied BEFORE host matching;
// file:// and bare paths bypass host matching and require an exact entry.
inline bool UriPolicyMatch(const std::string &uri, const std::vector<ResourcePolicy> &policies) {
	if (policies.empty())
		return false; // default-deny
	std::string scheme = UriScheme(uri);
	std::string host = UriHost(uri);
	bool scheme_ok = (scheme == "https" || scheme == "quack");
	for (const auto &p : policies) {
		if (p.pattern == "*")
			return true; // full wildcard
		// Exact URI match (covers file:// URIs with explicit entries and any scheme).
		if (p.pattern == uri)
			return true;
		// Host-based match: only for allowed-scheme URIs.
		if (scheme_ok && !host.empty() && HostMatch(p.pattern, host))
			return true;
	}
	return false;
}

// Match an extension name against a policy list.
// `name` is the extension identifier (bare name like "birdshot" or a path).
// Policy entries are exact extension names or "*" (wildcard).
// Path-form extension names (containing '/') require an exact entry — they can
// reach the filesystem and must not match a bare-name entry.
inline bool ExtNameMatch(const std::string &name, const std::vector<ResourcePolicy> &policies) {
	if (policies.empty())
		return false; // default-deny
	bool is_path = (name.find('/') != std::string::npos || name.find('\\') != std::string::npos);
	for (const auto &p : policies) {
		if (p.pattern == "*" && !is_path)
			return true; // wildcard covers bare names only; paths need explicit entry
		if (p.pattern == name)
			return true; // exact match (covers paths)
	}
	return false;
}

// Match an ATTACH path/DSN against a policy list.
// `path` is the raw AttachInfo.path string (may be a DSN like
// "postgresql://host/db", a file path, or a quack:// DSN).
// Matching follows the same URI rules as UriPolicyMatch for URL-shaped paths,
// and exact-entry matching for file paths (which are denied by default unless
// an explicit file:// pattern is present).
inline bool AttachTargetMatch(const std::string &path, const std::vector<ResourcePolicy> &policies) {
	if (policies.empty())
		return false; // default-deny
	// Treat it as a URI if it contains "://", else as an opaque string.
	bool is_uri = (path.find("://") != std::string::npos);
	if (is_uri) {
		// Reuse URI matching; AttachInfo paths can be quack:// or postgresql:// DSNs.
		// Note: only "https" and "quack" get automatic host-pattern matching;
		// other schemes (postgresql://, etc.) require an exact entry.
		return UriPolicyMatch(path, policies);
	}
	// Non-URI (bare file path or relative path): require an exact entry or "*".
	for (const auto &p : policies) {
		if (p.pattern == "*" || p.pattern == path)
			return true;
	}
	return false;
}

} // namespace birdshot
