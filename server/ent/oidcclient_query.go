// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/koalatea/authserver/server/ent/oidcclient"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// OIDCClientQuery is the builder for querying OIDCClient entities.
type OIDCClientQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.OIDCClient
	modifiers  []func(*sql.Selector)
	loadTotal  []func(context.Context, []*OIDCClient) error
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the OIDCClientQuery builder.
func (ocq *OIDCClientQuery) Where(ps ...predicate.OIDCClient) *OIDCClientQuery {
	ocq.predicates = append(ocq.predicates, ps...)
	return ocq
}

// Limit adds a limit step to the query.
func (ocq *OIDCClientQuery) Limit(limit int) *OIDCClientQuery {
	ocq.limit = &limit
	return ocq
}

// Offset adds an offset step to the query.
func (ocq *OIDCClientQuery) Offset(offset int) *OIDCClientQuery {
	ocq.offset = &offset
	return ocq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (ocq *OIDCClientQuery) Unique(unique bool) *OIDCClientQuery {
	ocq.unique = &unique
	return ocq
}

// Order adds an order step to the query.
func (ocq *OIDCClientQuery) Order(o ...OrderFunc) *OIDCClientQuery {
	ocq.order = append(ocq.order, o...)
	return ocq
}

// First returns the first OIDCClient entity from the query.
// Returns a *NotFoundError when no OIDCClient was found.
func (ocq *OIDCClientQuery) First(ctx context.Context) (*OIDCClient, error) {
	nodes, err := ocq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{oidcclient.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (ocq *OIDCClientQuery) FirstX(ctx context.Context) *OIDCClient {
	node, err := ocq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first OIDCClient ID from the query.
// Returns a *NotFoundError when no OIDCClient ID was found.
func (ocq *OIDCClientQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = ocq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{oidcclient.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (ocq *OIDCClientQuery) FirstIDX(ctx context.Context) int {
	id, err := ocq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single OIDCClient entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one OIDCClient entity is found.
// Returns a *NotFoundError when no OIDCClient entities are found.
func (ocq *OIDCClientQuery) Only(ctx context.Context) (*OIDCClient, error) {
	nodes, err := ocq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{oidcclient.Label}
	default:
		return nil, &NotSingularError{oidcclient.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (ocq *OIDCClientQuery) OnlyX(ctx context.Context) *OIDCClient {
	node, err := ocq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only OIDCClient ID in the query.
// Returns a *NotSingularError when more than one OIDCClient ID is found.
// Returns a *NotFoundError when no entities are found.
func (ocq *OIDCClientQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = ocq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{oidcclient.Label}
	default:
		err = &NotSingularError{oidcclient.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (ocq *OIDCClientQuery) OnlyIDX(ctx context.Context) int {
	id, err := ocq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of OIDCClients.
func (ocq *OIDCClientQuery) All(ctx context.Context) ([]*OIDCClient, error) {
	if err := ocq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return ocq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (ocq *OIDCClientQuery) AllX(ctx context.Context) []*OIDCClient {
	nodes, err := ocq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of OIDCClient IDs.
func (ocq *OIDCClientQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := ocq.Select(oidcclient.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (ocq *OIDCClientQuery) IDsX(ctx context.Context) []int {
	ids, err := ocq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (ocq *OIDCClientQuery) Count(ctx context.Context) (int, error) {
	if err := ocq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return ocq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (ocq *OIDCClientQuery) CountX(ctx context.Context) int {
	count, err := ocq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (ocq *OIDCClientQuery) Exist(ctx context.Context) (bool, error) {
	if err := ocq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return ocq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (ocq *OIDCClientQuery) ExistX(ctx context.Context) bool {
	exist, err := ocq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the OIDCClientQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (ocq *OIDCClientQuery) Clone() *OIDCClientQuery {
	if ocq == nil {
		return nil
	}
	return &OIDCClientQuery{
		config:     ocq.config,
		limit:      ocq.limit,
		offset:     ocq.offset,
		order:      append([]OrderFunc{}, ocq.order...),
		predicates: append([]predicate.OIDCClient{}, ocq.predicates...),
		// clone intermediate query.
		sql:    ocq.sql.Clone(),
		path:   ocq.path,
		unique: ocq.unique,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		ClientID string `json:"client_id,omitempty"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.OIDCClient.Query().
//		GroupBy(oidcclient.FieldClientID).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (ocq *OIDCClientQuery) GroupBy(field string, fields ...string) *OIDCClientGroupBy {
	grbuild := &OIDCClientGroupBy{config: ocq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := ocq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return ocq.sqlQuery(ctx), nil
	}
	grbuild.label = oidcclient.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		ClientID string `json:"client_id,omitempty"`
//	}
//
//	client.OIDCClient.Query().
//		Select(oidcclient.FieldClientID).
//		Scan(ctx, &v)
func (ocq *OIDCClientQuery) Select(fields ...string) *OIDCClientSelect {
	ocq.fields = append(ocq.fields, fields...)
	selbuild := &OIDCClientSelect{OIDCClientQuery: ocq}
	selbuild.label = oidcclient.Label
	selbuild.flds, selbuild.scan = &ocq.fields, selbuild.Scan
	return selbuild
}

// Aggregate returns a OIDCClientSelect configured with the given aggregations.
func (ocq *OIDCClientQuery) Aggregate(fns ...AggregateFunc) *OIDCClientSelect {
	return ocq.Select().Aggregate(fns...)
}

func (ocq *OIDCClientQuery) prepareQuery(ctx context.Context) error {
	for _, f := range ocq.fields {
		if !oidcclient.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if ocq.path != nil {
		prev, err := ocq.path(ctx)
		if err != nil {
			return err
		}
		ocq.sql = prev
	}
	return nil
}

func (ocq *OIDCClientQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*OIDCClient, error) {
	var (
		nodes = []*OIDCClient{}
		_spec = ocq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*OIDCClient).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &OIDCClient{config: ocq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	if len(ocq.modifiers) > 0 {
		_spec.Modifiers = ocq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, ocq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	for i := range ocq.loadTotal {
		if err := ocq.loadTotal[i](ctx, nodes); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func (ocq *OIDCClientQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := ocq.querySpec()
	if len(ocq.modifiers) > 0 {
		_spec.Modifiers = ocq.modifiers
	}
	_spec.Node.Columns = ocq.fields
	if len(ocq.fields) > 0 {
		_spec.Unique = ocq.unique != nil && *ocq.unique
	}
	return sqlgraph.CountNodes(ctx, ocq.driver, _spec)
}

func (ocq *OIDCClientQuery) sqlExist(ctx context.Context) (bool, error) {
	switch _, err := ocq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

func (ocq *OIDCClientQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   oidcclient.Table,
			Columns: oidcclient.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: oidcclient.FieldID,
			},
		},
		From:   ocq.sql,
		Unique: true,
	}
	if unique := ocq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := ocq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oidcclient.FieldID)
		for i := range fields {
			if fields[i] != oidcclient.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := ocq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := ocq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := ocq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := ocq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (ocq *OIDCClientQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(ocq.driver.Dialect())
	t1 := builder.Table(oidcclient.Table)
	columns := ocq.fields
	if len(columns) == 0 {
		columns = oidcclient.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if ocq.sql != nil {
		selector = ocq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if ocq.unique != nil && *ocq.unique {
		selector.Distinct()
	}
	for _, p := range ocq.predicates {
		p(selector)
	}
	for _, p := range ocq.order {
		p(selector)
	}
	if offset := ocq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := ocq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// OIDCClientGroupBy is the group-by builder for OIDCClient entities.
type OIDCClientGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (ocgb *OIDCClientGroupBy) Aggregate(fns ...AggregateFunc) *OIDCClientGroupBy {
	ocgb.fns = append(ocgb.fns, fns...)
	return ocgb
}

// Scan applies the group-by query and scans the result into the given value.
func (ocgb *OIDCClientGroupBy) Scan(ctx context.Context, v any) error {
	query, err := ocgb.path(ctx)
	if err != nil {
		return err
	}
	ocgb.sql = query
	return ocgb.sqlScan(ctx, v)
}

func (ocgb *OIDCClientGroupBy) sqlScan(ctx context.Context, v any) error {
	for _, f := range ocgb.fields {
		if !oidcclient.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := ocgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ocgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (ocgb *OIDCClientGroupBy) sqlQuery() *sql.Selector {
	selector := ocgb.sql.Select()
	aggregation := make([]string, 0, len(ocgb.fns))
	for _, fn := range ocgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(ocgb.fields)+len(ocgb.fns))
		for _, f := range ocgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(ocgb.fields...)...)
}

// OIDCClientSelect is the builder for selecting fields of OIDCClient entities.
type OIDCClientSelect struct {
	*OIDCClientQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ocs *OIDCClientSelect) Aggregate(fns ...AggregateFunc) *OIDCClientSelect {
	ocs.fns = append(ocs.fns, fns...)
	return ocs
}

// Scan applies the selector query and scans the result into the given value.
func (ocs *OIDCClientSelect) Scan(ctx context.Context, v any) error {
	if err := ocs.prepareQuery(ctx); err != nil {
		return err
	}
	ocs.sql = ocs.OIDCClientQuery.sqlQuery(ctx)
	return ocs.sqlScan(ctx, v)
}

func (ocs *OIDCClientSelect) sqlScan(ctx context.Context, v any) error {
	aggregation := make([]string, 0, len(ocs.fns))
	for _, fn := range ocs.fns {
		aggregation = append(aggregation, fn(ocs.sql))
	}
	switch n := len(*ocs.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		ocs.sql.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		ocs.sql.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := ocs.sql.Query()
	if err := ocs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
