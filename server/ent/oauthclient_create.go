// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/koalatea/authserver/server/ent/oauthclient"
)

// OAuthClientCreate is the builder for creating a OAuthClient entity.
type OAuthClientCreate struct {
	config
	mutation *OAuthClientMutation
	hooks    []Hook
}

// SetClientID sets the "client_id" field.
func (occ *OAuthClientCreate) SetClientID(s string) *OAuthClientCreate {
	occ.mutation.SetClientID(s)
	return occ
}

// SetSecret sets the "secret" field.
func (occ *OAuthClientCreate) SetSecret(s string) *OAuthClientCreate {
	occ.mutation.SetSecret(s)
	return occ
}

// SetRedirectUris sets the "redirect_uris" field.
func (occ *OAuthClientCreate) SetRedirectUris(s []string) *OAuthClientCreate {
	occ.mutation.SetRedirectUris(s)
	return occ
}

// SetResponseTypes sets the "response_types" field.
func (occ *OAuthClientCreate) SetResponseTypes(s []string) *OAuthClientCreate {
	occ.mutation.SetResponseTypes(s)
	return occ
}

// SetGrantTypes sets the "grant_types" field.
func (occ *OAuthClientCreate) SetGrantTypes(s []string) *OAuthClientCreate {
	occ.mutation.SetGrantTypes(s)
	return occ
}

// SetScopes sets the "scopes" field.
func (occ *OAuthClientCreate) SetScopes(s []string) *OAuthClientCreate {
	occ.mutation.SetScopes(s)
	return occ
}

// Mutation returns the OAuthClientMutation object of the builder.
func (occ *OAuthClientCreate) Mutation() *OAuthClientMutation {
	return occ.mutation
}

// Save creates the OAuthClient in the database.
func (occ *OAuthClientCreate) Save(ctx context.Context) (*OAuthClient, error) {
	var (
		err  error
		node *OAuthClient
	)
	if len(occ.hooks) == 0 {
		if err = occ.check(); err != nil {
			return nil, err
		}
		node, err = occ.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*OAuthClientMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = occ.check(); err != nil {
				return nil, err
			}
			occ.mutation = mutation
			if node, err = occ.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(occ.hooks) - 1; i >= 0; i-- {
			if occ.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = occ.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, occ.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*OAuthClient)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from OAuthClientMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (occ *OAuthClientCreate) SaveX(ctx context.Context) *OAuthClient {
	v, err := occ.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (occ *OAuthClientCreate) Exec(ctx context.Context) error {
	_, err := occ.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (occ *OAuthClientCreate) ExecX(ctx context.Context) {
	if err := occ.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (occ *OAuthClientCreate) check() error {
	if _, ok := occ.mutation.ClientID(); !ok {
		return &ValidationError{Name: "client_id", err: errors.New(`ent: missing required field "OAuthClient.client_id"`)}
	}
	if _, ok := occ.mutation.Secret(); !ok {
		return &ValidationError{Name: "secret", err: errors.New(`ent: missing required field "OAuthClient.secret"`)}
	}
	if _, ok := occ.mutation.RedirectUris(); !ok {
		return &ValidationError{Name: "redirect_uris", err: errors.New(`ent: missing required field "OAuthClient.redirect_uris"`)}
	}
	if _, ok := occ.mutation.ResponseTypes(); !ok {
		return &ValidationError{Name: "response_types", err: errors.New(`ent: missing required field "OAuthClient.response_types"`)}
	}
	if _, ok := occ.mutation.GrantTypes(); !ok {
		return &ValidationError{Name: "grant_types", err: errors.New(`ent: missing required field "OAuthClient.grant_types"`)}
	}
	if _, ok := occ.mutation.Scopes(); !ok {
		return &ValidationError{Name: "scopes", err: errors.New(`ent: missing required field "OAuthClient.scopes"`)}
	}
	return nil
}

func (occ *OAuthClientCreate) sqlSave(ctx context.Context) (*OAuthClient, error) {
	_node, _spec := occ.createSpec()
	if err := sqlgraph.CreateNode(ctx, occ.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (occ *OAuthClientCreate) createSpec() (*OAuthClient, *sqlgraph.CreateSpec) {
	var (
		_node = &OAuthClient{config: occ.config}
		_spec = &sqlgraph.CreateSpec{
			Table: oauthclient.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: oauthclient.FieldID,
			},
		}
	)
	if value, ok := occ.mutation.ClientID(); ok {
		_spec.SetField(oauthclient.FieldClientID, field.TypeString, value)
		_node.ClientID = value
	}
	if value, ok := occ.mutation.Secret(); ok {
		_spec.SetField(oauthclient.FieldSecret, field.TypeString, value)
		_node.Secret = value
	}
	if value, ok := occ.mutation.RedirectUris(); ok {
		_spec.SetField(oauthclient.FieldRedirectUris, field.TypeJSON, value)
		_node.RedirectUris = value
	}
	if value, ok := occ.mutation.ResponseTypes(); ok {
		_spec.SetField(oauthclient.FieldResponseTypes, field.TypeJSON, value)
		_node.ResponseTypes = value
	}
	if value, ok := occ.mutation.GrantTypes(); ok {
		_spec.SetField(oauthclient.FieldGrantTypes, field.TypeJSON, value)
		_node.GrantTypes = value
	}
	if value, ok := occ.mutation.Scopes(); ok {
		_spec.SetField(oauthclient.FieldScopes, field.TypeJSON, value)
		_node.Scopes = value
	}
	return _node, _spec
}

// OAuthClientCreateBulk is the builder for creating many OAuthClient entities in bulk.
type OAuthClientCreateBulk struct {
	config
	builders []*OAuthClientCreate
}

// Save creates the OAuthClient entities in the database.
func (occb *OAuthClientCreateBulk) Save(ctx context.Context) ([]*OAuthClient, error) {
	specs := make([]*sqlgraph.CreateSpec, len(occb.builders))
	nodes := make([]*OAuthClient, len(occb.builders))
	mutators := make([]Mutator, len(occb.builders))
	for i := range occb.builders {
		func(i int, root context.Context) {
			builder := occb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*OAuthClientMutation)
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
					_, err = mutators[i+1].Mutate(root, occb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, occb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, occb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (occb *OAuthClientCreateBulk) SaveX(ctx context.Context) []*OAuthClient {
	v, err := occb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (occb *OAuthClientCreateBulk) Exec(ctx context.Context) error {
	_, err := occb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (occb *OAuthClientCreateBulk) ExecX(ctx context.Context) {
	if err := occb.Exec(ctx); err != nil {
		panic(err)
	}
}
