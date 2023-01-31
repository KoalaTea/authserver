// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/koalatea/authserver/server/ent/accessrequest"
)

// AccessRequestCreate is the builder for creating a AccessRequest entity.
type AccessRequestCreate struct {
	config
	mutation *AccessRequestMutation
	hooks    []Hook
}

// SetRequestedScopes sets the "requested_scopes" field.
func (arc *AccessRequestCreate) SetRequestedScopes(s []string) *AccessRequestCreate {
	arc.mutation.SetRequestedScopes(s)
	return arc
}

// SetGrantedScopes sets the "granted_scopes" field.
func (arc *AccessRequestCreate) SetGrantedScopes(s []string) *AccessRequestCreate {
	arc.mutation.SetGrantedScopes(s)
	return arc
}

// SetRequestedAudiences sets the "requested_audiences" field.
func (arc *AccessRequestCreate) SetRequestedAudiences(s []string) *AccessRequestCreate {
	arc.mutation.SetRequestedAudiences(s)
	return arc
}

// SetGrantedAudiences sets the "granted_audiences" field.
func (arc *AccessRequestCreate) SetGrantedAudiences(s []string) *AccessRequestCreate {
	arc.mutation.SetGrantedAudiences(s)
	return arc
}

// SetRequest sets the "request" field.
func (arc *AccessRequestCreate) SetRequest(s string) *AccessRequestCreate {
	arc.mutation.SetRequest(s)
	return arc
}

// SetForm sets the "form" field.
func (arc *AccessRequestCreate) SetForm(s string) *AccessRequestCreate {
	arc.mutation.SetForm(s)
	return arc
}

// SetActive sets the "active" field.
func (arc *AccessRequestCreate) SetActive(b bool) *AccessRequestCreate {
	arc.mutation.SetActive(b)
	return arc
}

// Mutation returns the AccessRequestMutation object of the builder.
func (arc *AccessRequestCreate) Mutation() *AccessRequestMutation {
	return arc.mutation
}

// Save creates the AccessRequest in the database.
func (arc *AccessRequestCreate) Save(ctx context.Context) (*AccessRequest, error) {
	var (
		err  error
		node *AccessRequest
	)
	if len(arc.hooks) == 0 {
		if err = arc.check(); err != nil {
			return nil, err
		}
		node, err = arc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*AccessRequestMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = arc.check(); err != nil {
				return nil, err
			}
			arc.mutation = mutation
			if node, err = arc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(arc.hooks) - 1; i >= 0; i-- {
			if arc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = arc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, arc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*AccessRequest)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from AccessRequestMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (arc *AccessRequestCreate) SaveX(ctx context.Context) *AccessRequest {
	v, err := arc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (arc *AccessRequestCreate) Exec(ctx context.Context) error {
	_, err := arc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (arc *AccessRequestCreate) ExecX(ctx context.Context) {
	if err := arc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (arc *AccessRequestCreate) check() error {
	if _, ok := arc.mutation.RequestedScopes(); !ok {
		return &ValidationError{Name: "requested_scopes", err: errors.New(`ent: missing required field "AccessRequest.requested_scopes"`)}
	}
	if _, ok := arc.mutation.GrantedScopes(); !ok {
		return &ValidationError{Name: "granted_scopes", err: errors.New(`ent: missing required field "AccessRequest.granted_scopes"`)}
	}
	if _, ok := arc.mutation.RequestedAudiences(); !ok {
		return &ValidationError{Name: "requested_audiences", err: errors.New(`ent: missing required field "AccessRequest.requested_audiences"`)}
	}
	if _, ok := arc.mutation.GrantedAudiences(); !ok {
		return &ValidationError{Name: "granted_audiences", err: errors.New(`ent: missing required field "AccessRequest.granted_audiences"`)}
	}
	if _, ok := arc.mutation.Request(); !ok {
		return &ValidationError{Name: "request", err: errors.New(`ent: missing required field "AccessRequest.request"`)}
	}
	if _, ok := arc.mutation.Form(); !ok {
		return &ValidationError{Name: "form", err: errors.New(`ent: missing required field "AccessRequest.form"`)}
	}
	if _, ok := arc.mutation.Active(); !ok {
		return &ValidationError{Name: "active", err: errors.New(`ent: missing required field "AccessRequest.active"`)}
	}
	return nil
}

func (arc *AccessRequestCreate) sqlSave(ctx context.Context) (*AccessRequest, error) {
	_node, _spec := arc.createSpec()
	if err := sqlgraph.CreateNode(ctx, arc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (arc *AccessRequestCreate) createSpec() (*AccessRequest, *sqlgraph.CreateSpec) {
	var (
		_node = &AccessRequest{config: arc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: accessrequest.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: accessrequest.FieldID,
			},
		}
	)
	if value, ok := arc.mutation.RequestedScopes(); ok {
		_spec.SetField(accessrequest.FieldRequestedScopes, field.TypeJSON, value)
		_node.RequestedScopes = value
	}
	if value, ok := arc.mutation.GrantedScopes(); ok {
		_spec.SetField(accessrequest.FieldGrantedScopes, field.TypeJSON, value)
		_node.GrantedScopes = value
	}
	if value, ok := arc.mutation.RequestedAudiences(); ok {
		_spec.SetField(accessrequest.FieldRequestedAudiences, field.TypeJSON, value)
		_node.RequestedAudiences = value
	}
	if value, ok := arc.mutation.GrantedAudiences(); ok {
		_spec.SetField(accessrequest.FieldGrantedAudiences, field.TypeJSON, value)
		_node.GrantedAudiences = value
	}
	if value, ok := arc.mutation.Request(); ok {
		_spec.SetField(accessrequest.FieldRequest, field.TypeString, value)
		_node.Request = value
	}
	if value, ok := arc.mutation.Form(); ok {
		_spec.SetField(accessrequest.FieldForm, field.TypeString, value)
		_node.Form = value
	}
	if value, ok := arc.mutation.Active(); ok {
		_spec.SetField(accessrequest.FieldActive, field.TypeBool, value)
		_node.Active = value
	}
	return _node, _spec
}

// AccessRequestCreateBulk is the builder for creating many AccessRequest entities in bulk.
type AccessRequestCreateBulk struct {
	config
	builders []*AccessRequestCreate
}

// Save creates the AccessRequest entities in the database.
func (arcb *AccessRequestCreateBulk) Save(ctx context.Context) ([]*AccessRequest, error) {
	specs := make([]*sqlgraph.CreateSpec, len(arcb.builders))
	nodes := make([]*AccessRequest, len(arcb.builders))
	mutators := make([]Mutator, len(arcb.builders))
	for i := range arcb.builders {
		func(i int, root context.Context) {
			builder := arcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AccessRequestMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, arcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, arcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, arcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (arcb *AccessRequestCreateBulk) SaveX(ctx context.Context) []*AccessRequest {
	v, err := arcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (arcb *AccessRequestCreateBulk) Exec(ctx context.Context) error {
	_, err := arcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (arcb *AccessRequestCreateBulk) ExecX(ctx context.Context) {
	if err := arcb.Exec(ctx); err != nil {
		panic(err)
	}
}