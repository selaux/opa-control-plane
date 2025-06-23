package authz

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/v1/dependencies"
)

//go:embed authz.rego
var src string

// Any references to `data` documents in the authorization policy are considered
// references to SQL tables and therefore are marked as unknowns by default. In addition,
// we assume that columns are always referred to via `data.<tablename>.<columnname>`.
//
// This function extracts the unknowns and column references from the policy for the
// partial evaluation and query translation (respectively) below.
var defaultUnknowns, defaultColumnMappings = func() ([]string, map[string]sqlColumnRef) {

	deps, err := dependencies.Minimal(ast.MustParseModule(src))
	if err != nil {
		panic(err)
	}

	var unknowns []string
	columns := make(map[string]sqlColumnRef)

	for _, dep := range deps {
		if dep[0].Equal(ast.DefaultRootDocument) {
			table := string(dep[1].Value.(ast.String))
			column := string(dep[2].Value.(ast.String))
			columns[dep.String()] = sqlColumnRef{Table: table, Column: column}
			unknowns = append(unknowns, dep[:2].String())
		}
	}

	return unknowns, columns
}()

type sqlSelect struct {
	Select []sqlExpr
	From   []sqlTableRef
	Where  sqlWhere
}

type sqlWhere struct {
	expr sqlExpr
}

func (x sqlWhere) And(other sqlExpr) sqlWhere {
	if x.expr == nil {
		return sqlWhere{other}
	}
	return sqlWhere{sqlExprAnd{x.expr, other}}
}

func (x sqlWhere) Or(other sqlExpr) sqlWhere {
	if x.expr == nil {
		return sqlWhere{other}
	}
	return sqlWhere{sqlExprOr{x.expr, other}}
}

func (x sqlWhere) Tables() []sqlTableRef { return x.expr.Tables() }

type sqlExpr interface {
	SQL() string
	Tables() []sqlTableRef
}

type sqlExprExists struct {
	Query sqlSelect
}

func (x sqlExprExists) Tables() []sqlTableRef {
	return x.Query.From
}

type sqlExprAnd struct {
	LHS sqlExpr
	RHS sqlExpr
}

func (x sqlExprAnd) Tables() []sqlTableRef {
	return append(x.LHS.Tables(), x.RHS.Tables()...)
}

type sqlExprOr struct {
	LHS sqlExpr
	RHS sqlExpr
}

func (x sqlExprOr) Tables() []sqlTableRef {
	return append(x.LHS.Tables(), x.RHS.Tables()...)
}

type sqlExprEq struct {
	LHS sqlOperand
	RHS sqlOperand
}

func (x sqlExprEq) Tables() []sqlTableRef {
	return append(x.LHS.Tables(), x.RHS.Tables()...)
}

type sqlExprIsNotNull struct {
	Column sqlColumnRef
}

func (e sqlExprIsNotNull) Tables() []sqlTableRef {
	return e.Column.Tables()
}

type sqlTableRef struct {
	Table string
}

type sqlOperand interface {
	Tables() []sqlTableRef
	SQL() string
}

type sqlColumnRef struct {
	Table  string
	Column string
}

func (c sqlColumnRef) Tables() []sqlTableRef {
	return []sqlTableRef{{Table: c.Table}}
}

type sqlString struct {
	Value string
}

type sqlInt struct {
	Value int
}

func (x sqlSelect) SQL() string {
	tables := make([]string, len(x.From))
	for i := range tables {
		tables[i] = x.From[i].SQL()
	}
	selects := make([]string, len(x.Select))
	for i := range selects {
		selects[i] = x.Select[i].SQL()
	}
	return "SELECT " + strings.Join(selects, ", ") + " FROM " + strings.Join(tables, ", ") + " WHERE " + x.Where.expr.SQL()
}

func (x sqlExprExists) SQL() string    { return "EXISTS (" + x.Query.SQL() + ")" }
func (x sqlExprAnd) SQL() string       { return x.LHS.SQL() + " AND " + x.RHS.SQL() }
func (x sqlExprOr) SQL() string        { return x.LHS.SQL() + " OR " + x.RHS.SQL() }
func (x sqlExprEq) SQL() string        { return x.LHS.SQL() + "=" + x.RHS.SQL() }
func (x sqlExprIsNotNull) SQL() string { return x.Column.SQL() + " IS NOT NULL" }
func (x sqlTableRef) SQL() string      { return x.Table }
func (x sqlColumnRef) SQL() string     { return x.Table + "." + x.Column }
func (x sqlInt) SQL() string           { return strconv.Itoa(x.Value) }
func (x sqlString) SQL() string        { return "'" + x.Value + "'" }

func (sqlString) Tables() []sqlTableRef { return nil }
func (sqlInt) Tables() []sqlTableRef    { return nil }

type Access struct {
	Principal  string `json:"principal"`
	Resource   string `json:"resource"`
	Permission string `json:"permission"`
	Id         string `json:"id,omitempty"`
}

func Check(ctx context.Context, tx *sql.Tx, access Access) bool {

	expr, err := Partial(ctx, access, nil)
	if err != nil {
		return false
	}

	var x any

	return tx.QueryRowContext(ctx, `SELECT 1 WHERE `+expr.SQL()).Scan(&x) == nil
}

// TODO(tsandall): add caching
// TODO(tsandall): decide how to expose column mapping outside this package

func Partial(ctx context.Context, access Access, extraColumnMappings map[string]sqlColumnRef) (sqlExpr, error) {

	var extraUnknowns []string
	for k := range extraColumnMappings {
		extraUnknowns = append(extraUnknowns, k)
	}

	pqs, err := rego.New(
		rego.Query("data.authz.allow = true"),
		rego.Module("authz.rego", src),
		rego.Unknowns(append(extraUnknowns, defaultUnknowns...)),
		rego.Input(access),
	).Partial(ctx)
	if err != nil {
		return nil, err
	}

	if len(pqs.Support) > 0 {
		return nil, fmt.Errorf("unsupported authorization result (support modules found)")
	}

	cm := columnMapper(defaultColumnMappings)
	if len(extraColumnMappings) > 0 {
		cm = make(columnMapper, len(cm)+len(extraColumnMappings))
		maps.Copy(cm, defaultColumnMappings)
		maps.Copy(cm, extraColumnMappings)
	}

	var w sqlWhere

	for _, b := range pqs.Queries {

		var exists sqlExprExists
		exists.Query.Select = []sqlExpr{sqlInt{Value: 1}}

		for _, expr := range b {
			op := expr.Operator()
			switch op.String() {
			case "eq":
				lhs := cm.toSqlOp(expr.Operand(0))
				rhs := cm.toSqlOp(expr.Operand(1))
				if lhs == nil || rhs == nil {
					return nil, fmt.Errorf("XXX: translation error: eq operands: %v", expr)
				}
				exists.Query.Where = exists.Query.Where.And(sqlExprEq{LHS: lhs, RHS: rhs})
			case "neq":
				if e, ok := cm.trySqlExprIsNotNull(expr.Operand(0), expr.Operand(1)); ok {
					exists.Query.Where = exists.Query.Where.And(e)
				} else if e, ok := cm.trySqlExprIsNotNull(expr.Operand(1), expr.Operand(0)); ok {
					exists.Query.Where = exists.Query.Where.And(e)
				} else {
					return nil, fmt.Errorf("XXX: translation error: neq operands")
				}
			default:
				return nil, fmt.Errorf("XXX: translation error: expr operator")
			}
		}

		seen := map[sqlTableRef]struct{}{}

		for _, t := range exists.Query.Where.Tables() {
			if t.Table != access.Resource {
				seen[t] = struct{}{}
			}
		}

		for t := range seen {
			exists.Query.From = append(exists.Query.From, t)
		}

		sort.Slice(exists.Query.From, func(i, j int) bool {
			return exists.Query.From[i].Table < exists.Query.From[j].Table
		})

		w = w.Or(exists)
	}

	return w.expr, nil
}

type columnMapper map[string]sqlColumnRef

func (cm columnMapper) trySqlExprIsNotNull(a, b *ast.Term) (sqlExpr, bool) {
	if r, ok := a.Value.(ast.Ref); ok {
		if _, ok := b.Value.(ast.Null); ok {
			if c, ok := cm.trySqlColumnOperand(r); ok {
				return sqlExprIsNotNull{Column: c}, true
			}
		}
	}
	return sqlExprIsNotNull{}, false
}

func (cm columnMapper) toSqlOp(t *ast.Term) sqlOperand {
	switch tv := t.Value.(type) {
	case ast.Ref:
		if c, ok := cm.trySqlColumnOperand(tv); ok {
			return c
		}
	case ast.String:
		return sqlString{Value: string(tv)}
	}
	return nil
}

func (cm columnMapper) trySqlColumnOperand(ref ast.Ref) (sqlColumnRef, bool) {
	if c, ok := cm[ref.String()]; ok {
		return c, true
	}
	return sqlColumnRef{}, false
}
