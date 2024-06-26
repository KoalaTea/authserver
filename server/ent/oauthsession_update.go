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
	"github.com/koalatea/authserver/server/ent/oauthsession"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// OAuthSessionUpdate is the builder for updating OAuthSession entities.
type OAuthSessionUpdate struct {
	config
	hooks    []Hook
	mutation *OAuthSessionMutation
}

// Where appends a list predicates to the OAuthSessionUpdate builder.
func (osu *OAuthSessionUpdate) Where(ps ...predicate.OAuthSession) *OAuthSessionUpdate {
	osu.mutation.Where(ps...)
	return osu
}

// SetIssuer sets the "issuer" field.
func (osu *OAuthSessionUpdate) SetIssuer(s string) *OAuthSessionUpdate {
	osu.mutation.SetIssuer(s)
	return osu
}

// SetNillableIssuer sets the "issuer" field if the given value is not nil.
func (osu *OAuthSessionUpdate) SetNillableIssuer(s *string) *OAuthSessionUpdate {
	if s != nil {
		osu.SetIssuer(*s)
	}
	return osu
}

// SetSubject sets the "subject" field.
func (osu *OAuthSessionUpdate) SetSubject(s string) *OAuthSessionUpdate {
	osu.mutation.SetSubject(s)
	return osu
}

// SetNillableSubject sets the "subject" field if the given value is not nil.
func (osu *OAuthSessionUpdate) SetNillableSubject(s *string) *OAuthSessionUpdate {
	if s != nil {
		osu.SetSubject(*s)
	}
	return osu
}

// SetAudiences sets the "audiences" field.
func (osu *OAuthSessionUpdate) SetAudiences(s []string) *OAuthSessionUpdate {
	osu.mutation.SetAudiences(s)
	return osu
}

// AppendAudiences appends s to the "audiences" field.
func (osu *OAuthSessionUpdate) AppendAudiences(s []string) *OAuthSessionUpdate {
	osu.mutation.AppendAudiences(s)
	return osu
}

// SetExpiresAt sets the "expires_at" field.
func (osu *OAuthSessionUpdate) SetExpiresAt(t time.Time) *OAuthSessionUpdate {
	osu.mutation.SetExpiresAt(t)
	return osu
}

// SetNillableExpiresAt sets the "expires_at" field if the given value is not nil.
func (osu *OAuthSessionUpdate) SetNillableExpiresAt(t *time.Time) *OAuthSessionUpdate {
	if t != nil {
		osu.SetExpiresAt(*t)
	}
	return osu
}

// SetIssuedAt sets the "issued_at" field.
func (osu *OAuthSessionUpdate) SetIssuedAt(t time.Time) *OAuthSessionUpdate {
	osu.mutation.SetIssuedAt(t)
	return osu
}

// SetNillableIssuedAt sets the "issued_at" field if the given value is not nil.
func (osu *OAuthSessionUpdate) SetNillableIssuedAt(t *time.Time) *OAuthSessionUpdate {
	if t != nil {
		osu.SetIssuedAt(*t)
	}
	return osu
}

// SetRequestedAt sets the "requested_at" field.
func (osu *OAuthSessionUpdate) SetRequestedAt(t time.Time) *OAuthSessionUpdate {
	osu.mutation.SetRequestedAt(t)
	return osu
}

// SetNillableRequestedAt sets the "requested_at" field if the given value is not nil.
func (osu *OAuthSessionUpdate) SetNillableRequestedAt(t *time.Time) *OAuthSessionUpdate {
	if t != nil {
		osu.SetRequestedAt(*t)
	}
	return osu
}

// SetAuthTime sets the "auth_time" field.
func (osu *OAuthSessionUpdate) SetAuthTime(t time.Time) *OAuthSessionUpdate {
	osu.mutation.SetAuthTime(t)
	return osu
}

// SetNillableAuthTime sets the "auth_time" field if the given value is not nil.
func (osu *OAuthSessionUpdate) SetNillableAuthTime(t *time.Time) *OAuthSessionUpdate {
	if t != nil {
		osu.SetAuthTime(*t)
	}
	return osu
}

// SetRequestedScopes sets the "requested_scopes" field.
func (osu *OAuthSessionUpdate) SetRequestedScopes(s []string) *OAuthSessionUpdate {
	osu.mutation.SetRequestedScopes(s)
	return osu
}

// AppendRequestedScopes appends s to the "requested_scopes" field.
func (osu *OAuthSessionUpdate) AppendRequestedScopes(s []string) *OAuthSessionUpdate {
	osu.mutation.AppendRequestedScopes(s)
	return osu
}

// SetGrantedScopes sets the "granted_scopes" field.
func (osu *OAuthSessionUpdate) SetGrantedScopes(s []string) *OAuthSessionUpdate {
	osu.mutation.SetGrantedScopes(s)
	return osu
}

// AppendGrantedScopes appends s to the "granted_scopes" field.
func (osu *OAuthSessionUpdate) AppendGrantedScopes(s []string) *OAuthSessionUpdate {
	osu.mutation.AppendGrantedScopes(s)
	return osu
}

// SetRequestedAudiences sets the "requested_audiences" field.
func (osu *OAuthSessionUpdate) SetRequestedAudiences(s []string) *OAuthSessionUpdate {
	osu.mutation.SetRequestedAudiences(s)
	return osu
}

// AppendRequestedAudiences appends s to the "requested_audiences" field.
func (osu *OAuthSessionUpdate) AppendRequestedAudiences(s []string) *OAuthSessionUpdate {
	osu.mutation.AppendRequestedAudiences(s)
	return osu
}

// SetGrantedAudiences sets the "granted_audiences" field.
func (osu *OAuthSessionUpdate) SetGrantedAudiences(s []string) *OAuthSessionUpdate {
	osu.mutation.SetGrantedAudiences(s)
	return osu
}

// AppendGrantedAudiences appends s to the "granted_audiences" field.
func (osu *OAuthSessionUpdate) AppendGrantedAudiences(s []string) *OAuthSessionUpdate {
	osu.mutation.AppendGrantedAudiences(s)
	return osu
}

// SetRequest sets the "request" field.
func (osu *OAuthSessionUpdate) SetRequest(s string) *OAuthSessionUpdate {
	osu.mutation.SetRequest(s)
	return osu
}

// SetNillableRequest sets the "request" field if the given value is not nil.
func (osu *OAuthSessionUpdate) SetNillableRequest(s *string) *OAuthSessionUpdate {
	if s != nil {
		osu.SetRequest(*s)
	}
	return osu
}

// SetForm sets the "form" field.
func (osu *OAuthSessionUpdate) SetForm(s string) *OAuthSessionUpdate {
	osu.mutation.SetForm(s)
	return osu
}

// SetNillableForm sets the "form" field if the given value is not nil.
func (osu *OAuthSessionUpdate) SetNillableForm(s *string) *OAuthSessionUpdate {
	if s != nil {
		osu.SetForm(*s)
	}
	return osu
}

// Mutation returns the OAuthSessionMutation object of the builder.
func (osu *OAuthSessionUpdate) Mutation() *OAuthSessionMutation {
	return osu.mutation
}

// Save executes the query and returns the number of nodes affected by the update operation.
func (osu *OAuthSessionUpdate) Save(ctx context.Context) (int, error) {
	return withHooks(ctx, osu.sqlSave, osu.mutation, osu.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (osu *OAuthSessionUpdate) SaveX(ctx context.Context) int {
	affected, err := osu.Save(ctx)
	if err != nil {
		panic(err)
	}
	return affected
}

// Exec executes the query.
func (osu *OAuthSessionUpdate) Exec(ctx context.Context) error {
	_, err := osu.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (osu *OAuthSessionUpdate) ExecX(ctx context.Context) {
	if err := osu.Exec(ctx); err != nil {
		panic(err)
	}
}

func (osu *OAuthSessionUpdate) sqlSave(ctx context.Context) (n int, err error) {
	_spec := sqlgraph.NewUpdateSpec(oauthsession.Table, oauthsession.Columns, sqlgraph.NewFieldSpec(oauthsession.FieldID, field.TypeInt))
	if ps := osu.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if value, ok := osu.mutation.Issuer(); ok {
		_spec.SetField(oauthsession.FieldIssuer, field.TypeString, value)
	}
	if value, ok := osu.mutation.Subject(); ok {
		_spec.SetField(oauthsession.FieldSubject, field.TypeString, value)
	}
	if value, ok := osu.mutation.Audiences(); ok {
		_spec.SetField(oauthsession.FieldAudiences, field.TypeJSON, value)
	}
	if value, ok := osu.mutation.AppendedAudiences(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldAudiences, value)
		})
	}
	if value, ok := osu.mutation.ExpiresAt(); ok {
		_spec.SetField(oauthsession.FieldExpiresAt, field.TypeTime, value)
	}
	if value, ok := osu.mutation.IssuedAt(); ok {
		_spec.SetField(oauthsession.FieldIssuedAt, field.TypeTime, value)
	}
	if value, ok := osu.mutation.RequestedAt(); ok {
		_spec.SetField(oauthsession.FieldRequestedAt, field.TypeTime, value)
	}
	if value, ok := osu.mutation.AuthTime(); ok {
		_spec.SetField(oauthsession.FieldAuthTime, field.TypeTime, value)
	}
	if value, ok := osu.mutation.RequestedScopes(); ok {
		_spec.SetField(oauthsession.FieldRequestedScopes, field.TypeJSON, value)
	}
	if value, ok := osu.mutation.AppendedRequestedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldRequestedScopes, value)
		})
	}
	if value, ok := osu.mutation.GrantedScopes(); ok {
		_spec.SetField(oauthsession.FieldGrantedScopes, field.TypeJSON, value)
	}
	if value, ok := osu.mutation.AppendedGrantedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldGrantedScopes, value)
		})
	}
	if value, ok := osu.mutation.RequestedAudiences(); ok {
		_spec.SetField(oauthsession.FieldRequestedAudiences, field.TypeJSON, value)
	}
	if value, ok := osu.mutation.AppendedRequestedAudiences(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldRequestedAudiences, value)
		})
	}
	if value, ok := osu.mutation.GrantedAudiences(); ok {
		_spec.SetField(oauthsession.FieldGrantedAudiences, field.TypeJSON, value)
	}
	if value, ok := osu.mutation.AppendedGrantedAudiences(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldGrantedAudiences, value)
		})
	}
	if value, ok := osu.mutation.Request(); ok {
		_spec.SetField(oauthsession.FieldRequest, field.TypeString, value)
	}
	if value, ok := osu.mutation.Form(); ok {
		_spec.SetField(oauthsession.FieldForm, field.TypeString, value)
	}
	if n, err = sqlgraph.UpdateNodes(ctx, osu.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oauthsession.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return 0, err
	}
	osu.mutation.done = true
	return n, nil
}

// OAuthSessionUpdateOne is the builder for updating a single OAuthSession entity.
type OAuthSessionUpdateOne struct {
	config
	fields   []string
	hooks    []Hook
	mutation *OAuthSessionMutation
}

// SetIssuer sets the "issuer" field.
func (osuo *OAuthSessionUpdateOne) SetIssuer(s string) *OAuthSessionUpdateOne {
	osuo.mutation.SetIssuer(s)
	return osuo
}

// SetNillableIssuer sets the "issuer" field if the given value is not nil.
func (osuo *OAuthSessionUpdateOne) SetNillableIssuer(s *string) *OAuthSessionUpdateOne {
	if s != nil {
		osuo.SetIssuer(*s)
	}
	return osuo
}

// SetSubject sets the "subject" field.
func (osuo *OAuthSessionUpdateOne) SetSubject(s string) *OAuthSessionUpdateOne {
	osuo.mutation.SetSubject(s)
	return osuo
}

// SetNillableSubject sets the "subject" field if the given value is not nil.
func (osuo *OAuthSessionUpdateOne) SetNillableSubject(s *string) *OAuthSessionUpdateOne {
	if s != nil {
		osuo.SetSubject(*s)
	}
	return osuo
}

// SetAudiences sets the "audiences" field.
func (osuo *OAuthSessionUpdateOne) SetAudiences(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.SetAudiences(s)
	return osuo
}

// AppendAudiences appends s to the "audiences" field.
func (osuo *OAuthSessionUpdateOne) AppendAudiences(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.AppendAudiences(s)
	return osuo
}

// SetExpiresAt sets the "expires_at" field.
func (osuo *OAuthSessionUpdateOne) SetExpiresAt(t time.Time) *OAuthSessionUpdateOne {
	osuo.mutation.SetExpiresAt(t)
	return osuo
}

// SetNillableExpiresAt sets the "expires_at" field if the given value is not nil.
func (osuo *OAuthSessionUpdateOne) SetNillableExpiresAt(t *time.Time) *OAuthSessionUpdateOne {
	if t != nil {
		osuo.SetExpiresAt(*t)
	}
	return osuo
}

// SetIssuedAt sets the "issued_at" field.
func (osuo *OAuthSessionUpdateOne) SetIssuedAt(t time.Time) *OAuthSessionUpdateOne {
	osuo.mutation.SetIssuedAt(t)
	return osuo
}

// SetNillableIssuedAt sets the "issued_at" field if the given value is not nil.
func (osuo *OAuthSessionUpdateOne) SetNillableIssuedAt(t *time.Time) *OAuthSessionUpdateOne {
	if t != nil {
		osuo.SetIssuedAt(*t)
	}
	return osuo
}

// SetRequestedAt sets the "requested_at" field.
func (osuo *OAuthSessionUpdateOne) SetRequestedAt(t time.Time) *OAuthSessionUpdateOne {
	osuo.mutation.SetRequestedAt(t)
	return osuo
}

// SetNillableRequestedAt sets the "requested_at" field if the given value is not nil.
func (osuo *OAuthSessionUpdateOne) SetNillableRequestedAt(t *time.Time) *OAuthSessionUpdateOne {
	if t != nil {
		osuo.SetRequestedAt(*t)
	}
	return osuo
}

// SetAuthTime sets the "auth_time" field.
func (osuo *OAuthSessionUpdateOne) SetAuthTime(t time.Time) *OAuthSessionUpdateOne {
	osuo.mutation.SetAuthTime(t)
	return osuo
}

// SetNillableAuthTime sets the "auth_time" field if the given value is not nil.
func (osuo *OAuthSessionUpdateOne) SetNillableAuthTime(t *time.Time) *OAuthSessionUpdateOne {
	if t != nil {
		osuo.SetAuthTime(*t)
	}
	return osuo
}

// SetRequestedScopes sets the "requested_scopes" field.
func (osuo *OAuthSessionUpdateOne) SetRequestedScopes(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.SetRequestedScopes(s)
	return osuo
}

// AppendRequestedScopes appends s to the "requested_scopes" field.
func (osuo *OAuthSessionUpdateOne) AppendRequestedScopes(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.AppendRequestedScopes(s)
	return osuo
}

// SetGrantedScopes sets the "granted_scopes" field.
func (osuo *OAuthSessionUpdateOne) SetGrantedScopes(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.SetGrantedScopes(s)
	return osuo
}

// AppendGrantedScopes appends s to the "granted_scopes" field.
func (osuo *OAuthSessionUpdateOne) AppendGrantedScopes(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.AppendGrantedScopes(s)
	return osuo
}

// SetRequestedAudiences sets the "requested_audiences" field.
func (osuo *OAuthSessionUpdateOne) SetRequestedAudiences(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.SetRequestedAudiences(s)
	return osuo
}

// AppendRequestedAudiences appends s to the "requested_audiences" field.
func (osuo *OAuthSessionUpdateOne) AppendRequestedAudiences(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.AppendRequestedAudiences(s)
	return osuo
}

// SetGrantedAudiences sets the "granted_audiences" field.
func (osuo *OAuthSessionUpdateOne) SetGrantedAudiences(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.SetGrantedAudiences(s)
	return osuo
}

// AppendGrantedAudiences appends s to the "granted_audiences" field.
func (osuo *OAuthSessionUpdateOne) AppendGrantedAudiences(s []string) *OAuthSessionUpdateOne {
	osuo.mutation.AppendGrantedAudiences(s)
	return osuo
}

// SetRequest sets the "request" field.
func (osuo *OAuthSessionUpdateOne) SetRequest(s string) *OAuthSessionUpdateOne {
	osuo.mutation.SetRequest(s)
	return osuo
}

// SetNillableRequest sets the "request" field if the given value is not nil.
func (osuo *OAuthSessionUpdateOne) SetNillableRequest(s *string) *OAuthSessionUpdateOne {
	if s != nil {
		osuo.SetRequest(*s)
	}
	return osuo
}

// SetForm sets the "form" field.
func (osuo *OAuthSessionUpdateOne) SetForm(s string) *OAuthSessionUpdateOne {
	osuo.mutation.SetForm(s)
	return osuo
}

// SetNillableForm sets the "form" field if the given value is not nil.
func (osuo *OAuthSessionUpdateOne) SetNillableForm(s *string) *OAuthSessionUpdateOne {
	if s != nil {
		osuo.SetForm(*s)
	}
	return osuo
}

// Mutation returns the OAuthSessionMutation object of the builder.
func (osuo *OAuthSessionUpdateOne) Mutation() *OAuthSessionMutation {
	return osuo.mutation
}

// Where appends a list predicates to the OAuthSessionUpdate builder.
func (osuo *OAuthSessionUpdateOne) Where(ps ...predicate.OAuthSession) *OAuthSessionUpdateOne {
	osuo.mutation.Where(ps...)
	return osuo
}

// Select allows selecting one or more fields (columns) of the returned entity.
// The default is selecting all fields defined in the entity schema.
func (osuo *OAuthSessionUpdateOne) Select(field string, fields ...string) *OAuthSessionUpdateOne {
	osuo.fields = append([]string{field}, fields...)
	return osuo
}

// Save executes the query and returns the updated OAuthSession entity.
func (osuo *OAuthSessionUpdateOne) Save(ctx context.Context) (*OAuthSession, error) {
	return withHooks(ctx, osuo.sqlSave, osuo.mutation, osuo.hooks)
}

// SaveX is like Save, but panics if an error occurs.
func (osuo *OAuthSessionUpdateOne) SaveX(ctx context.Context) *OAuthSession {
	node, err := osuo.Save(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// Exec executes the query on the entity.
func (osuo *OAuthSessionUpdateOne) Exec(ctx context.Context) error {
	_, err := osuo.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (osuo *OAuthSessionUpdateOne) ExecX(ctx context.Context) {
	if err := osuo.Exec(ctx); err != nil {
		panic(err)
	}
}

func (osuo *OAuthSessionUpdateOne) sqlSave(ctx context.Context) (_node *OAuthSession, err error) {
	_spec := sqlgraph.NewUpdateSpec(oauthsession.Table, oauthsession.Columns, sqlgraph.NewFieldSpec(oauthsession.FieldID, field.TypeInt))
	id, ok := osuo.mutation.ID()
	if !ok {
		return nil, &ValidationError{Name: "id", err: errors.New(`ent: missing "OAuthSession.id" for update`)}
	}
	_spec.Node.ID.Value = id
	if fields := osuo.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, oauthsession.FieldID)
		for _, f := range fields {
			if !oauthsession.ValidColumn(f) {
				return nil, &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
			}
			if f != oauthsession.FieldID {
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
		_spec.SetField(oauthsession.FieldIssuer, field.TypeString, value)
	}
	if value, ok := osuo.mutation.Subject(); ok {
		_spec.SetField(oauthsession.FieldSubject, field.TypeString, value)
	}
	if value, ok := osuo.mutation.Audiences(); ok {
		_spec.SetField(oauthsession.FieldAudiences, field.TypeJSON, value)
	}
	if value, ok := osuo.mutation.AppendedAudiences(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldAudiences, value)
		})
	}
	if value, ok := osuo.mutation.ExpiresAt(); ok {
		_spec.SetField(oauthsession.FieldExpiresAt, field.TypeTime, value)
	}
	if value, ok := osuo.mutation.IssuedAt(); ok {
		_spec.SetField(oauthsession.FieldIssuedAt, field.TypeTime, value)
	}
	if value, ok := osuo.mutation.RequestedAt(); ok {
		_spec.SetField(oauthsession.FieldRequestedAt, field.TypeTime, value)
	}
	if value, ok := osuo.mutation.AuthTime(); ok {
		_spec.SetField(oauthsession.FieldAuthTime, field.TypeTime, value)
	}
	if value, ok := osuo.mutation.RequestedScopes(); ok {
		_spec.SetField(oauthsession.FieldRequestedScopes, field.TypeJSON, value)
	}
	if value, ok := osuo.mutation.AppendedRequestedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldRequestedScopes, value)
		})
	}
	if value, ok := osuo.mutation.GrantedScopes(); ok {
		_spec.SetField(oauthsession.FieldGrantedScopes, field.TypeJSON, value)
	}
	if value, ok := osuo.mutation.AppendedGrantedScopes(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldGrantedScopes, value)
		})
	}
	if value, ok := osuo.mutation.RequestedAudiences(); ok {
		_spec.SetField(oauthsession.FieldRequestedAudiences, field.TypeJSON, value)
	}
	if value, ok := osuo.mutation.AppendedRequestedAudiences(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldRequestedAudiences, value)
		})
	}
	if value, ok := osuo.mutation.GrantedAudiences(); ok {
		_spec.SetField(oauthsession.FieldGrantedAudiences, field.TypeJSON, value)
	}
	if value, ok := osuo.mutation.AppendedGrantedAudiences(); ok {
		_spec.AddModifier(func(u *sql.UpdateBuilder) {
			sqljson.Append(u, oauthsession.FieldGrantedAudiences, value)
		})
	}
	if value, ok := osuo.mutation.Request(); ok {
		_spec.SetField(oauthsession.FieldRequest, field.TypeString, value)
	}
	if value, ok := osuo.mutation.Form(); ok {
		_spec.SetField(oauthsession.FieldForm, field.TypeString, value)
	}
	_node = &OAuthSession{config: osuo.config}
	_spec.Assign = _node.assignValues
	_spec.ScanValues = _node.scanValues
	if err = sqlgraph.UpdateNode(ctx, osuo.driver, _spec); err != nil {
		if _, ok := err.(*sqlgraph.NotFoundError); ok {
			err = &NotFoundError{oauthsession.Label}
		} else if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	osuo.mutation.done = true
	return _node, nil
}
