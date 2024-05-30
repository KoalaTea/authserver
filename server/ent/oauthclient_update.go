// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/dialect/sql/sqljson"
	"entgo.io/ent/schema/field"
	"github.com/koalatea/authserver/server/ent/oauthclient"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// OAuthClientUpdate is the builder for updating OAuthClient entities.
type OAuthClientUpdate struct {
	config
	hooks    []Hook
	mutation *OAuthClientMutation
}

// Where appends a list predicates to the OAuthClientUpdate builder.
func (ocu *OAuthClientUpdate) Where(ps ...predicate.OAuthClient) *OAuthClientUpdate {
	ocu.mutation.Where(ps...)
	return ocu
}

// SetClientID sets the "client_id" field.
func (ocu *OAuthClientUpdate) SetClientID(s string) *OAuthClientUpdate {
	ocu.mutation.SetClientID(s)
	return ocu
}

// SetNillableClientID sets the "client_id" field if the given value is not nil.
func (ocu *OAuthClientUpdate) SetNillableClientID(s *string) *OAuthClientUpdate {
	if s != nil {
		ocu.SetClientID(*s)
	}
	return ocu
}

// SetSecret sets the "secret" field.
func (ocu *OAuthClientUpdate) SetSecret(s string) *OAuthClientUpdate {
	ocu.mutation.SetSecret(s)
	return ocu
}

// SetNillableSecret sets the "secret" field if the given value is not nil.
func (ocu *OAuthClientUpdate) SetNillableSecret(s *string) *OAuthClientUpdate {
	if s != nil {
		ocu.SetSecret(*s)
	}
	return ocu
}

// SetRedirectUris sets the "redirect_uris" field.
func (ocu *OAuthClientUpdate) SetRedirectUris(s []string) *OAuthClientUpdate {
	ocu.mutation.SetRedirectUris(s)
	return ocu
}

// AppendRedirectUris appends s to the "redirect_uris" field.
func (ocu *OAuthClientUpdate) AppendRedirectUris(s []string) *OAuthClientUpdate {
	ocu.mutation.AppendRedirectUris(s)
	return ocu
}

// SetResponseTypes sets the "response_types" field.
func (ocu *OAuthClientUpdate) SetResponseTypes(s []string) *OAuthClientUpdate {
	ocu.mutation.SetResponseTypes(s)
	return ocu
}

// AppendResponseTypes appends s to the "response_types" field.
func (ocu *OAuthClientUpdate) AppendResponseTypes(s []string) *OAuthClientUpdate {
	ocu.mutation.AppendResponseTypes(s)
	return ocu
}

// SetGrantTypes sets the "grant_types" field.
func (ocu *OAuthClientUpdate) SetGrantTypes(s []string) *OAuthClientUpdate {
	ocu.mutation.SetGrantTypes(s)
	return ocu
}

// AppendGrantTypes appends s to the "grant_types" field.
func (ocu *OAuthClientUpdate) AppendGrantTypes(s []string) *OAuthClientUpdate {
	ocu.mutation.AppendGrantTypes(s)
	return ocu
}

// SetScopes sets the "scopes" field.
func (ocu *OAuthClientUpdate) SetScopes(s []string) *OAuthClientUpdate {
	ocu.mutation.SetScopes(s)
	return ocu
}

// AppendScopes appends s to the "scopes" field.
func (ocu *OAuthClientUpdate) AppendScopes(s []string) *OAuthClientUpdate {
	ocu.mutation.AppendScopes(s)
	return ocu
}

// Mutation returns the OAuthClientMutation object of the builder.
func (ocu *OAuthClientUpdate) Mutation() *OAuthClientMutation {
	return ocu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (ocu *OAuthClientUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, ocu.sqlSave, ocu.mutation, ocu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (ocu *OAuthClientUpdate) SaveX(ctx context.Context) int {
	affected, err := ocu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (ocu *OAuthClientUpdate) Exec(ctx context.Context) error {
	_, err := ocu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ocu *OAuthClientUpdate) ExecX(ctx context.Context) {
	if err := ocu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (ocu *OAuthClientUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(oauthclient.Table, oauthclient.Columns, sqlgraph.NewFieldSpec(oauthclient.FieldID, field.TypeInt))
	if ps := ocu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ocu.mutation.ClientID(); ok {
		_spec.SetField(oauthclient.FieldClientID, field.TypeString, value)
	}
	if value, ok := ocu.mutation.Secret(); ok {
		_spec.SetField(oauthclient.FieldSecret, field.TypeString, value)
	}
	if value, ok := ocu.mutation.RedirectUris(); ok {
		_spec.SetField(oauthclient.FieldRedirectUris, field.TypeJSON, value)
	}
	if value, ok := ocu.mutation.AppendedRedirectUris(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthclient.FieldRedirectUris, value)
		})
	}
	if value, ok := ocu.mutation.ResponseTypes(); ok {
		_spec.SetField(oauthclient.FieldResponseTypes, field.TypeJSON, value)
	}
	if value, ok := ocu.mutation.AppendedResponseTypes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthclient.FieldResponseTypes, value)
		})
	}
	if value, ok := ocu.mutation.GrantTypes(); ok {
		_spec.SetField(oauthclient.FieldGrantTypes, field.TypeJSON, value)
	}
	if value, ok := ocu.mutation.AppendedGrantTypes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthclient.FieldGrantTypes, value)
		})
	}
	if value, ok := ocu.mutation.Scopes(); ok {
		_spec.SetField(oauthclient.FieldScopes, field.TypeJSON, value)
	}
	if value, ok := ocu.mutation.AppendedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthclient.FieldScopes, value)
		})
	}
	if n, err = sqlgraph.UpdateNodes(ctx, ocu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oauthclient.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	ocu.mutation.done = true
	return n, nil
}

// OAuthClientUpdateOne is the builder for updating a single OAuthClient entity.
type OAuthClientUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *OAuthClientMutation
}

// SetClientID sets the "client_id" field.
func (ocuo *OAuthClientUpdateOne) SetClientID(s string) *OAuthClientUpdateOne {
	ocuo.mutation.SetClientID(s)
	return ocuo
}

// SetNillableClientID sets the "client_id" field if the given value is not nil.
func (ocuo *OAuthClientUpdateOne) SetNillableClientID(s *string) *OAuthClientUpdateOne {
	if s != nil {
		ocuo.SetClientID(*s)
	}
	return ocuo
}

// SetSecret sets the "secret" field.
func (ocuo *OAuthClientUpdateOne) SetSecret(s string) *OAuthClientUpdateOne {
	ocuo.mutation.SetSecret(s)
	return ocuo
}

// SetNillableSecret sets the "secret" field if the given value is not nil.
func (ocuo *OAuthClientUpdateOne) SetNillableSecret(s *string) *OAuthClientUpdateOne {
	if s != nil {
		ocuo.SetSecret(*s)
	}
	return ocuo
}

// SetRedirectUris sets the "redirect_uris" field.
func (ocuo *OAuthClientUpdateOne) SetRedirectUris(s []string) *OAuthClientUpdateOne {
	ocuo.mutation.SetRedirectUris(s)
	return ocuo
}

// AppendRedirectUris appends s to the "redirect_uris" field.
func (ocuo *OAuthClientUpdateOne) AppendRedirectUris(s []string) *OAuthClientUpdateOne {
	ocuo.mutation.AppendRedirectUris(s)
	return ocuo
}

// SetResponseTypes sets the "response_types" field.
func (ocuo *OAuthClientUpdateOne) SetResponseTypes(s []string) *OAuthClientUpdateOne {
	ocuo.mutation.SetResponseTypes(s)
	return ocuo
}

// AppendResponseTypes appends s to the "response_types" field.
func (ocuo *OAuthClientUpdateOne) AppendResponseTypes(s []string) *OAuthClientUpdateOne {
	ocuo.mutation.AppendResponseTypes(s)
	return ocuo
}

// SetGrantTypes sets the "grant_types" field.
func (ocuo *OAuthClientUpdateOne) SetGrantTypes(s []string) *OAuthClientUpdateOne {
	ocuo.mutation.SetGrantTypes(s)
	return ocuo
}

// AppendGrantTypes appends s to the "grant_types" field.
func (ocuo *OAuthClientUpdateOne) AppendGrantTypes(s []string) *OAuthClientUpdateOne {
	ocuo.mutation.AppendGrantTypes(s)
	return ocuo
}

// SetScopes sets the "scopes" field.
func (ocuo *OAuthClientUpdateOne) SetScopes(s []string) *OAuthClientUpdateOne {
	ocuo.mutation.SetScopes(s)
	return ocuo
}

// AppendScopes appends s to the "scopes" field.
func (ocuo *OAuthClientUpdateOne) AppendScopes(s []string) *OAuthClientUpdateOne {
	ocuo.mutation.AppendScopes(s)
	return ocuo
}

// Mutation returns the OAuthClientMutation object of the builder.
func (ocuo *OAuthClientUpdateOne) Mutation() *OAuthClientMutation {
	return ocuo.mutation
}

// Where appends a list predicates to the OAuthClientUpdate builder.
func (ocuo *OAuthClientUpdateOne) Where(ps ...predicate.OAuthClient) *OAuthClientUpdateOne {
	ocuo.mutation.Where(ps...)
	return ocuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (ocuo *OAuthClientUpdateOne) Select(field string, fields ...string) *OAuthClientUpdateOne {
	ocuo.fields = append([]string{field}, fields...)
	return ocuo
}

// Save executes the query and returns the updated OAuthClient entity.
func (ocuo *OAuthClientUpdateOne) Save(ctx context.Context) (*OAuthClient, error) {
	return withHooks(ctx, ocuo.sqlSave, ocuo.mutation, ocuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (ocuo *OAuthClientUpdateOne) SaveX(ctx context.Context) *OAuthClient {
	node, err := ocuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (ocuo *OAuthClientUpdateOne) Exec(ctx context.Context) error {
	_, err := ocuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ocuo *OAuthClientUpdateOne) ExecX(ctx context.Context) {
	if err := ocuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (ocuo *OAuthClientUpdateOne) sqlSave(ctx context.Context) (_node *OAuthClient, err error) {
	_spec := sqlgraph.NewUpdateSpec(oauthclient.Table, oauthclient.Columns, sqlgraph.NewFieldSpec(oauthclient.FieldID, field.TypeInt))
	id, ok := ocuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "OAuthClient.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := ocuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oauthclient.FieldID)
		for _, f := range fields {
			if !oauthclient.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != oauthclient.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, f)
			}
		}
	}
	if ps := ocuo.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := ocuo.mutation.ClientID(); ok {
		_spec.SetField(oauthclient.FieldClientID, field.TypeString, value)
	}
	if value, ok := ocuo.mutation.Secret(); ok {
		_spec.SetField(oauthclient.FieldSecret, field.TypeString, value)
	}
	if value, ok := ocuo.mutation.RedirectUris(); ok {
		_spec.SetField(oauthclient.FieldRedirectUris, field.TypeJSON, value)
	}
	if value, ok := ocuo.mutation.AppendedRedirectUris(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthclient.FieldRedirectUris, value)
		})
	}
	if value, ok := ocuo.mutation.ResponseTypes(); ok {
		_spec.SetField(oauthclient.FieldResponseTypes, field.TypeJSON, value)
	}
	if value, ok := ocuo.mutation.AppendedResponseTypes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthclient.FieldResponseTypes, value)
		})
	}
	if value, ok := ocuo.mutation.GrantTypes(); ok {
		_spec.SetField(oauthclient.FieldGrantTypes, field.TypeJSON, value)
	}
	if value, ok := ocuo.mutation.AppendedGrantTypes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthclient.FieldGrantTypes, value)
		})
	}
	if value, ok := ocuo.mutation.Scopes(); ok {
		_spec.SetField(oauthclient.FieldScopes, field.TypeJSON, value)
	}
	if value, ok := ocuo.mutation.AppendedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthclient.FieldScopes, value)
		})
	}
	_node = &OAuthClient{config: ocuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, ocuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oauthclient.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	ocuo.mutation.done = true
	return _node, nil
}
