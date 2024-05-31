// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/koalatea/authserver/server/ent/oauthaccesstoken"
	"github.com/koalatea/authserver/server/ent/oauthsession"
)

// OAuthAccessTokenCreate is the builder for creating a OAuthAccessToken entity.
type OAuthAccessTokenCreate struct {
	config
	mutation *OAuthAccessTokenMutation
	hooks    []Hook
}

// SetSignature sets the "signature" field.
func (oatc *OAuthAccessTokenCreate) SetSignature(s string) *OAuthAccessTokenCreate {
	oatc.mutation.SetSignature(s)
	return oatc
}

// SetSessionID sets the "session" edge to the OAuthSession entity by ID.
func (oatc *OAuthAccessTokenCreate) SetSessionID(id int) *OAuthAccessTokenCreate {
	oatc.mutation.SetSessionID(id)
	return oatc
}

// SetNillableSessionID sets the "session" edge to the OAuthSession entity by ID if the given value is not nil.
func (oatc *OAuthAccessTokenCreate) SetNillableSessionID(id *int) *OAuthAccessTokenCreate {
	if id != nil {
		oatc = oatc.SetSessionID(*id)
	}
	return oatc
}

// SetSession sets the "session" edge to the OAuthSession entity.
func (oatc *OAuthAccessTokenCreate) SetSession(o *OAuthSession) *OAuthAccessTokenCreate {
	return oatc.SetSessionID(o.ID)
}

// Mutation returns the OAuthAccessTokenMutation object of the builder.
func (oatc *OAuthAccessTokenCreate) Mutation() *OAuthAccessTokenMutation {
	return oatc.mutation
}

// Save creates the OAuthAccessToken in the database.
func (oatc *OAuthAccessTokenCreate) Save(ctx context.Context) (*OAuthAccessToken, error) {
	return withHooks(ctx, oatc.sqlSave, oatc.mutation, oatc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (oatc *OAuthAccessTokenCreate) SaveX(ctx context.Context) *OAuthAccessToken {
	v, err := oatc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (oatc *OAuthAccessTokenCreate) Exec(ctx context.Context) error {
	_, err := oatc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (oatc *OAuthAccessTokenCreate) ExecX(ctx context.Context) {
	if err := oatc.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (oatc *OAuthAccessTokenCreate) check() error {
	if _, ok := oatc.mutation.Signature(); !ok {
		return &ValidationError{Name: "signature", err: errors.New(`ent: missing required field "OAuthAccessToken.signature"`)}
	}
	return nil
}

func (oatc *OAuthAccessTokenCreate) sqlSave(ctx context.Context) (*OAuthAccessToken, error) {
	if err := oatc.check(); err != nil {
		return nil, err
	}
	_node, _spec := oatc.createSpec()
	if err := sqlgraph.CreateNode(ctx, oatc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	oatc.mutation.id = &_node.ID
	oatc.mutation.done = true
	return _node, nil
}

func (oatc *OAuthAccessTokenCreate) createSpec() (*OAuthAccessToken, *sqlgraph.CreateSpec) {
	var (
		_node = &OAuthAccessToken{config: oatc.config}
		_spec = sqlgraph.NewCreateSpec(oauthaccesstoken.Table, sqlgraph.NewFieldSpec(oauthaccesstoken.FieldID, field.TypeInt))
	)
	if value, ok := oatc.mutation.Signature(); ok {
		_spec.SetField(oauthaccesstoken.FieldSignature, field.TypeString, value)
		_node.Signature = value
	}
	if nodes := oatc.mutation.SessionIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: false,
			Table:   oauthaccesstoken.SessionTable,
			Columns: []string{oauthaccesstoken.SessionColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(oauthsession.FieldID, field.TypeInt),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.oauth_access_token_session = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OAuthAccessTokenCreateBulk is the builder for creating many OAuthAccessToken entities in bulk.
type OAuthAccessTokenCreateBulk struct {
	config
	err      error
	builders []*OAuthAccessTokenCreate
}

// Save creates the OAuthAccessToken entities in the database.
func (oatcb *OAuthAccessTokenCreateBulk) Save(ctx context.Context) ([]*OAuthAccessToken, error) {
	if oatcb.err != nil {
		return nil, oatcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(oatcb.builders))
	nodes := make([]*OAuthAccessToken, len(oatcb.builders))
	mutators := make([]Mutator, len(oatcb.builders))
	for i := range oatcb.builders {
		func(i int, root context.Context) {
			builder := oatcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*OAuthAccessTokenMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, oatcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, oatcb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, oatcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (oatcb *OAuthAccessTokenCreateBulk) SaveX(ctx context.Context) []*OAuthAccessToken {
	v, err := oatcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (oatcb *OAuthAccessTokenCreateBulk) Exec(ctx context.Context) error {
	_, err := oatcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (oatcb *OAuthAccessTokenCreateBulk) ExecX(ctx context.Context) {
	if err := oatcb.Exec(ctx); err != nil {
		panic(err)
	}
}
