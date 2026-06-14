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

#include "duckdb.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parsed_expression.hpp"
#include "duckdb/parser/parsed_expression_iterator.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/expression/subquery_expression.hpp"
#include "duckdb/parser/expression/window_expression.hpp"
#include "duckdb/parser/expression/cast_expression.hpp"
#include "duckdb/parser/query_node.hpp"
#include "duckdb/parser/query_node/select_node.hpp"
#include "duckdb/parser/query_node/set_operation_node.hpp"
#include "duckdb/parser/tableref.hpp"
#include "duckdb/parser/tableref/basetableref.hpp"
#include "duckdb/parser/tableref/joinref.hpp"
#include "duckdb/parser/tableref/subqueryref.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"
#include "duckdb/parser/statement/select_statement.hpp"
#include "duckdb/parser/statement/insert_statement.hpp"
#include "duckdb/parser/statement/update_statement.hpp"
#include "duckdb/parser/statement/delete_statement.hpp"
#include "duckdb/parser/statement/explain_statement.hpp"

namespace birdshot {

enum class AclClass {
	CHECK,     // proceed to per-table ACL check using `tables`
	ALLOW_ALL, // benign/handshake statement(s); no table ACL (PRAGMA, tx, zero-table)
	FORBIDDEN, // statement / function class a peer may never run
	PARSE_ERR, // could not parse / extract -> fail closed
};

struct TableUse {
	std::string ref; // joined non-empty parts: "[catalog.][schema.]table", lowercased
	bool write;
};

// Threaded through the walkers: accumulates tables and trips `forbidden` the
// moment a dangerous function / table function is seen.
struct WalkCtx {
	std::vector<TableUse> tables;
	bool forbidden = false;
	std::string reason;
};

struct AclAnalysis {
	AclClass cls = AclClass::PARSE_ERR;
	std::vector<TableUse> tables;
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
// (quack's ATTACH handshake scans duckdb_tables()/pragma_* etc.).
inline bool IsSafeTableFunc(const std::string &lname) {
	return lname.rfind("duckdb_", 0) == 0 || lname.rfind("pragma_", 0) == 0;
}

// A CAST to an extension/unknown type (json/geometry/inet/...) pulls that
// extension in at bind time — an autoload vector birdshot's statement deny can't
// see. At PARSE time such a type is an unresolved USER type (core types have
// concrete ids), so deny casts to USER types. A federation peer doing analytics
// over todos/PII never needs them.
inline bool IsAutoloadCastType(const duckdb::LogicalType &t) {
	// An unloaded extension type (e.g. JSON) parses as UNBOUND and is resolved at
	// bind time — which is when autoload fires. Core types have concrete ids.
	auto id = t.id();
	return id == duckdb::LogicalTypeId::UNBOUND || id == duckdb::LogicalTypeId::UNKNOWN;
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
	} else if (cls == ExpressionClass::CAST) {
		auto &ce = expr.Cast<CastExpression>();
		if (IsAutoloadCastType(ce.cast_type)) {
			ctx.forbidden = true;
			ctx.reason = "forbidden_cast:" + LowerCopy(ce.cast_type.ToString());
		}
	} else if (cls == ExpressionClass::SUBQUERY) {
		auto &sub = expr.Cast<SubqueryExpression>();
		if (sub.subquery && sub.subquery->node)
			WalkNode(*sub.subquery->node, ctx);
	}
	ParsedExpressionIterator::EnumerateChildren(expr, [&](const ParsedExpression &child) { WalkExpr(child, ctx); });
}

inline void WalkRef(const duckdb::TableRef &ref, WalkCtx &ctx) {
	using namespace duckdb;
	switch (ref.type) {
	case TableReferenceType::BASE_TABLE: {
		auto &bt = ref.Cast<BaseTableRef>();
		if (!IsSystemRef(bt.catalog_name, bt.schema_name, bt.table_name))
			ctx.tables.push_back({QualifyRef(bt.catalog_name, bt.schema_name, bt.table_name), false});
		break;
	}
	case TableReferenceType::JOIN: {
		auto &j = ref.Cast<JoinRef>();
		if (j.left)
			WalkRef(*j.left, ctx);
		if (j.right)
			WalkRef(*j.right, ctx);
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
		std::string fn;
		if (tf.function && tf.function->GetExpressionClass() == ExpressionClass::FUNCTION)
			fn = LowerCopy(tf.function->Cast<FunctionExpression>().function_name);
		if (fn.empty() || !IsSafeTableFunc(fn)) {
			ctx.forbidden = true;
			ctx.reason = "forbidden_tablefunc:" + fn;
		}
		break;
	}
	default:
		// EXPRESSION_LIST (VALUES), EMPTY, etc.: no catalog table.
		break;
	}
}

inline void WalkNode(const duckdb::QueryNode &node, WalkCtx &ctx) {
	using namespace duckdb;
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
		break;
	}
	case QueryNodeType::SET_OPERATION_NODE: {
		auto &so = node.Cast<SetOperationNode>();
		for (auto &child : so.children)
			if (child)
				WalkNode(*child, ctx);
		break;
	}
	default:
		break;
	}
	for (auto &kv : node.cte_map.map) {
		if (kv.second && kv.second->query && kv.second->query->node)
			WalkNode(*kv.second->query->node, ctx);
	}
}

inline void WalkRefAsWrite(const duckdb::TableRef &ref, WalkCtx &ctx) {
	using namespace duckdb;
	if (ref.type == TableReferenceType::BASE_TABLE) {
		auto &bt = ref.Cast<BaseTableRef>();
		if (!IsSystemRef(bt.catalog_name, bt.schema_name, bt.table_name))
			ctx.tables.push_back({QualifyRef(bt.catalog_name, bt.schema_name, bt.table_name), true});
	} else {
		WalkRef(ref, ctx);
	}
}

// ---- per-statement analysis ------------------------------------------------

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
		if (!IsSystemRef(s.catalog, s.schema, s.table))
			ctx.tables.push_back({QualifyRef(s.catalog, s.schema, s.table), true});
		if (s.select_statement && s.select_statement->node)
			WalkNode(*s.select_statement->node, ctx);
		return true;
	}
	case StatementType::UPDATE_STATEMENT: {
		auto &s = stmt.Cast<UpdateStatement>();
		if (s.table)
			WalkRefAsWrite(*s.table, ctx);
		if (s.from_table)
			WalkRef(*s.from_table, ctx);
		return true;
	}
	case StatementType::DELETE_STATEMENT: {
		auto &s = stmt.Cast<DeleteStatement>();
		if (s.table)
			WalkRefAsWrite(*s.table, ctx);
		for (auto &u : s.using_clauses)
			if (u)
				WalkRef(*u, ctx);
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
	default:
		// PRAGMA (reparses into engine statements that skip re-authorize; some
		// pragmas reach settings/file-write primitives), SET/RESET, ATTACH/DETACH,
		// INSTALL/LOAD, CALL, COPY/EXPORT/IMPORT, CREATE/DROP/ALTER, etc.
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
	a.cls = a.tables.empty() ? AclClass::ALLOW_ALL : AclClass::CHECK;
	return a;
}

} // namespace birdshot
