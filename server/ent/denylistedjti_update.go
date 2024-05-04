// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/koalatea/authserver/server/ent/denylistedjti"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// DenyListedJTIUpdate is the builder for updating DenyListedJTI entities.
type DenyListedJTIUpdate struct {
	config
	hooks    []Hook
	mutation *DenyListedJTIMutation
}

// Where appends a list predicates to the DenyListedJTIUpdate builder.
func (dlju *DenyListedJTIUpdate) Where(ps ...predicate.DenyListedJTI) *DenyListedJTIUpdate {
	dlju.mutation.Where(ps...)
	return dlju
}

// SetJti sets the "jti" field.
func (dlju *DenyListedJTIUpdate) SetJti(s string) *DenyListedJTIUpdate {
	dlju.mutation.SetJti(s)
	return dlju
}

// SetExpiration sets the "expiration" field.
func (dlju *DenyListedJTIUpdate) SetExpiration(t time.Time) *DenyListedJTIUpdate {
	dlju.mutation.SetExpiration(t)
	return dlju
}

// Mutation returns the DenyListedJTIMutation object of the builder.
func (dlju *DenyListedJTIUpdate) Mutation() *DenyListedJTIMutation {
	return dlju.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (dlju *DenyListedJTIUpdate) Save(ctx context.Context) (int, error) {
	var (
		err      error
		affected int
	)
	if len(dlju.hooks) == 0 {
		affected, err = dlju.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*DenyListedJTIMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			dlju.mutation = mutation
			affected, err = dlju.sqlSave(ctx)
			mutation.done = true
			return affected, err
		})
		for i := len(dlju.hooks) - 1; i >= 0; i-- {
			if dlju.hooks[i] == nil {
				return 0, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = dlju.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, dlju.mutation); err != nil {
			return 0, err
		}
	}
	return affected, err
}

// SaveX is like Save, but panics if an error occurs.
func (dlju *DenyListedJTIUpdate) SaveX(ctx context.Context) int {
	affected, err := dlju.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (dlju *DenyListedJTIUpdate) Exec(ctx context.Context) error {
	_, err := dlju.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dlju *DenyListedJTIUpdate) ExecX(ctx context.Context) {
	if err := dlju.Exec(ctx); err != nil {
		panic(err)
	}
}

func (dlju *DenyListedJTIUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   denylistedjti.Table,
			Columns: denylistedjti.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: denylistedjti.FieldID,
			},
		},
	}
	if ps := dlju.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := dlju.mutation.Jti(); ok {
		_spec.SetField(denylistedjti.FieldJti, field.TypeString, value)
	}
	if value, ok := dlju.mutation.Expiration(); ok {
		_spec.SetField(denylistedjti.FieldExpiration, field.TypeTime, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, dlju.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{denylistedjti.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	return n, nil
}

// DenyListedJTIUpdateOne is the builder for updating a single DenyListedJTI entity.
type DenyListedJTIUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *DenyListedJTIMutation
}

// SetJti sets the "jti" field.
func (dljuo *DenyListedJTIUpdateOne) SetJti(s string) *DenyListedJTIUpdateOne {
	dljuo.mutation.SetJti(s)
	return dljuo
}

// SetExpiration sets the "expiration" field.
func (dljuo *DenyListedJTIUpdateOne) SetExpiration(t time.Time) *DenyListedJTIUpdateOne {
	dljuo.mutation.SetExpiration(t)
	return dljuo
}

// Mutation returns the DenyListedJTIMutation object of the builder.
func (dljuo *DenyListedJTIUpdateOne) Mutation() *DenyListedJTIMutation {
	return dljuo.mutation
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (dljuo *DenyListedJTIUpdateOne) Select(field string, fields ...string) *DenyListedJTIUpdateOne {
	dljuo.fields = append([]string{field}, fields...)
	return dljuo
}

// Save executes the query and returns the updated DenyListedJTI entity.
func (dljuo *DenyListedJTIUpdateOne) Save(ctx context.Context) (*DenyListedJTI, error) {
	var (
		err  error
		node *DenyListedJTI
	)
	if len(dljuo.hooks) == 0 {
		node, err = dljuo.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*DenyListedJTIMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			dljuo.mutation = mutation
			node, err = dljuo.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(dljuo.hooks) - 1; i >= 0; i-- {
			if dljuo.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = dljuo.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, dljuo.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*DenyListedJTI)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from DenyListedJTIMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX is like Save, but panics if an error occurs.
func (dljuo *DenyListedJTIUpdateOne) SaveX(ctx context.Context) *DenyListedJTI {
	node, err := dljuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (dljuo *DenyListedJTIUpdateOne) Exec(ctx context.Context) error {
	_, err := dljuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (dljuo *DenyListedJTIUpdateOne) ExecX(ctx context.Context) {
	if err := dljuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (dljuo *DenyListedJTIUpdateOne) sqlSave(ctx context.Context) (_node *DenyListedJTI, err error) {
	_spec := &sqlgraph.UpdateSpec{
		Node: &sqlgraph.NodeSpec{
			Table:   denylistedjti.Table,
			Columns: denylistedjti.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: denylistedjti.FieldID,
			},
		},
	}
	id, ok := dljuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "DenyListedJTI.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := dljuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, denylistedjti.FieldID)
		for _, f := range fields {
			if !denylistedjti.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != denylistedjti.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := dljuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := dljuo.mutation.Jti(); ok {
		_spec.SetField(denylistedjti.FieldJti, field.TypeString, value)
	}
	if value, ok := dljuo.mutation.Expiration(); ok {
		_spec.SetField(denylistedjti.FieldExpiration, field.TypeTime, value)
	}
	_node = &DenyListedJTI{config: dljuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, dljuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{denylistedjti.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	return _node, nil
}
