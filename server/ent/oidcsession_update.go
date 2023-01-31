// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/dialect/sql/sqljson"
	"entgo.io/ent/schema/field"
	"github.com/koalatea/authserver/server/ent/oidcsession"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// OIDCSessionUpdate is the builder for updating OIDCSession entities.
type OIDCSessionUpdate struct {
	config
	hooks    []Hook
	mutation *OIDCSessionMutation
}

// Where appends a list predicates to the OIDCSessionUpdate builder.
func (osu *OIDCSessionUpdate) Where(ps ...predicate.OIDCSession) *OIDCSessionUpdate {
	osu.mutation.Where(ps...)
	return osu
}

// SetIssuer sets the "issuer" field.
func (osu *OIDCSessionUpdate) SetIssuer(s string) *OIDCSessionUpdate {
	osu.mutation.SetIssuer(s)
	return osu
}

// SetSubject sets the "subject" field.
func (osu *OIDCSessionUpdate) SetSubject(s string) *OIDCSessionUpdate {
	osu.mutation.SetSubject(s)
	return osu
}

// SetAudiences sets the "audiences" field.
func (osu *OIDCSessionUpdate) SetAudiences(s []string) *OIDCSessionUpdate {
	osu.mutation.SetAudiences(s)
	return osu
}

// AppendAudiences appends s to the "audiences" field.
func (osu *OIDCSessionUpdate) AppendAudiences(s []string) *OIDCSessionUpdate {
	osu.mutation.AppendAudiences(s)
	return osu
}

// SetExpiresAt sets the "expires_at" field.
func (osu *OIDCSessionUpdate) SetExpiresAt(t time.Time) *OIDCSessionUpdate {
	osu.mutation.SetExpiresAt(t)
	return osu
}

// SetIssuedAt sets the "issued_at" field.
func (osu *OIDCSessionUpdate) SetIssuedAt(t time.Time) *OIDCSessionUpdate {
	osu.mutation.SetIssuedAt(t)
	return osu
}

// SetRequestedAt sets the "requested_at" field.
func (osu *OIDCSessionUpdate) SetRequestedAt(t time.Time) *OIDCSessionUpdate {
	osu.mutation.SetRequestedAt(t)
	return osu
}

// SetAuthTime sets the "auth_time" field.
func (osu *OIDCSessionUpdate) SetAuthTime(t time.Time) *OIDCSessionUpdate {
	osu.mutation.SetAuthTime(t)
	return osu
}

// Mutation returns the OIDCSessionMutation object of the builder.
func (osu *OIDCSessionUpdate) Mutation() *OIDCSessionMutation {
	return osu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (osu *OIDCSessionUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(osu.hooks) == 0 {
		affected, err = osu.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*OIDCSessionMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			osu.mutation = mutation
			affected, err = osu.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(osu.hooks) - 1; i >= 0; i-- {
			if osu.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = osu.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, osu.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (osu *OIDCSessionUpdate) SaveX(ctx context.Context) int {
	affected, err := osu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (osu *OIDCSessionUpdate) Exec(ctx context.Context) error {
	_, err := osu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (osu *OIDCSessionUpdate) ExecX(ctx context.Context) {
	if err := osu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (osu *OIDCSessionUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   oidcsession.Table,
			Columns: oidcsession.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: oidcsession.FieldID,
			},
		},
	}
	if ps := osu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := osu.mutation.Issuer(); ok {
		_spec.SetField(oidcsession.FieldIssuer, field.TypeString, value)
	}
	if value, ok := osu.mutation.Subject(); ok {
		_spec.SetField(oidcsession.FieldSubject, field.TypeString, value)
	}
	if value, ok := osu.mutation.Audiences(); ok {
		_spec.SetField(oidcsession.FieldAudiences, field.TypeJSON, value)
	}
	if value, ok := osu.mutation.AppendedAudiences(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oidcsession.FieldAudiences, value)
		})
	}
	if value, ok := osu.mutation.ExpiresAt(); ok {
		_spec.SetField(oidcsession.FieldExpiresAt, field.TypeTime, value)
	}
	if value, ok := osu.mutation.IssuedAt(); ok {
		_spec.SetField(oidcsession.FieldIssuedAt, field.TypeTime, value)
	}
	if value, ok := osu.mutation.RequestedAt(); ok {
		_spec.SetField(oidcsession.FieldRequestedAt, field.TypeTime, value)
	}
	if value, ok := osu.mutation.AuthTime(); ok {
		_spec.SetField(oidcsession.FieldAuthTime, field.TypeTime, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, osu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oidcsession.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// OIDCSessionUpdateOne is the builder for updating a single OIDCSession entity.
type OIDCSessionUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *OIDCSessionMutation
}

// SetIssuer sets the "issuer" field.
func (osuo *OIDCSessionUpdateOne) SetIssuer(s string) *OIDCSessionUpdateOne {
	osuo.mutation.SetIssuer(s)
	return osuo
}

// SetSubject sets the "subject" field.
func (osuo *OIDCSessionUpdateOne) SetSubject(s string) *OIDCSessionUpdateOne {
	osuo.mutation.SetSubject(s)
	return osuo
}

// SetAudiences sets the "audiences" field.
func (osuo *OIDCSessionUpdateOne) SetAudiences(s []string) *OIDCSessionUpdateOne {
	osuo.mutation.SetAudiences(s)
	return osuo
}

// AppendAudiences appends s to the "audiences" field.
func (osuo *OIDCSessionUpdateOne) AppendAudiences(s []string) *OIDCSessionUpdateOne {
	osuo.mutation.AppendAudiences(s)
	return osuo
}

// SetExpiresAt sets the "expires_at" field.
func (osuo *OIDCSessionUpdateOne) SetExpiresAt(t time.Time) *OIDCSessionUpdateOne {
	osuo.mutation.SetExpiresAt(t)
	return osuo
}

// SetIssuedAt sets the "issued_at" field.
func (osuo *OIDCSessionUpdateOne) SetIssuedAt(t time.Time) *OIDCSessionUpdateOne {
	osuo.mutation.SetIssuedAt(t)
	return osuo
}

// SetRequestedAt sets the "requested_at" field.
func (osuo *OIDCSessionUpdateOne) SetRequestedAt(t time.Time) *OIDCSessionUpdateOne {
	osuo.mutation.SetRequestedAt(t)
	return osuo
}

// SetAuthTime sets the "auth_time" field.
func (osuo *OIDCSessionUpdateOne) SetAuthTime(t time.Time) *OIDCSessionUpdateOne {
	osuo.mutation.SetAuthTime(t)
	return osuo
}

// Mutation returns the OIDCSessionMutation object of the builder.
func (osuo *OIDCSessionUpdateOne) Mutation() *OIDCSessionMutation {
	return osuo.mutation
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (osuo *OIDCSessionUpdateOne) Select(field string, fields ...string) *OIDCSessionUpdateOne {
	osuo.fields = append([]string{field}, fields...)
	return osuo
}

// Save executes the query and returns the updated OIDCSession entity.
func (osuo *OIDCSessionUpdateOne) Save(ctx context.Context) (*OIDCSession, error) {
	var (
		err  error
		node *OIDCSession
	)
	if len(osuo.hooks) == 0 {
		node, err = osuo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*OIDCSessionMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			osuo.mutation = mutation
			node, err = osuo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(osuo.hooks) - 1; i >= 0; i-- {
			if osuo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = osuo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, osuo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*OIDCSession)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from OIDCSessionMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (osuo *OIDCSessionUpdateOne) SaveX(ctx context.Context) *OIDCSession {
	node, err := osuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (osuo *OIDCSessionUpdateOne) Exec(ctx context.Context) error {
	_, err := osuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (osuo *OIDCSessionUpdateOne) ExecX(ctx context.Context) {
	if err := osuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (osuo *OIDCSessionUpdateOne) sqlSave(ctx context.Context) (_node *OIDCSession, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   oidcsession.Table,
			Columns: oidcsession.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: oidcsession.FieldID,
			},
		},
	}
	id, ok := osuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "OIDCSession.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := osuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oidcsession.FieldID)
		for _, f := range fields {
			if !oidcsession.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != oidcsession.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := osuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := osuo.mutation.Issuer(); ok {
		_spec.SetField(oidcsession.FieldIssuer, field.TypeString, value)
	}
	if value, ok := osuo.mutation.Subject(); ok {
		_spec.SetField(oidcsession.FieldSubject, field.TypeString, value)
	}
	if value, ok := osuo.mutation.Audiences(); ok {
		_spec.SetField(oidcsession.FieldAudiences, field.TypeJSON, value)
	}
	if value, ok := osuo.mutation.AppendedAudiences(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oidcsession.FieldAudiences, value)
		})
	}
	if value, ok := osuo.mutation.ExpiresAt(); ok {
		_spec.SetField(oidcsession.FieldExpiresAt, field.TypeTime, value)
	}
	if value, ok := osuo.mutation.IssuedAt(); ok {
		_spec.SetField(oidcsession.FieldIssuedAt, field.TypeTime, value)
	}
	if value, ok := osuo.mutation.RequestedAt(); ok {
		_spec.SetField(oidcsession.FieldRequestedAt, field.TypeTime, value)
	}
	if value, ok := osuo.mutation.AuthTime(); ok {
		_spec.SetField(oidcsession.FieldAuthTime, field.TypeTime, value)
	}
	_node = &OIDCSession{config: osuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, osuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oidcsession.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}