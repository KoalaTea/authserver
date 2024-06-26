// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/koalatea/authserver/server/ent/oauthparrequest"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// OAuthPARRequestDelete is the builder for deleting a OAuthPARRequest entity.
type OAuthPARRequestDelete struct {
	config
	hooks    []Hook
	mutation *OAuthPARRequestMutation
}

// Where appends a list predicates to the OAuthPARRequestDelete builder.
func (oprd *OAuthPARRequestDelete) Where(ps ...predicate.OAuthPARRequest) *OAuthPARRequestDelete {
	oprd.mutation.Where(ps...)
	return oprd
}

// Exec executes the deletion query and returns how many vertices were deleted.
func (oprd *OAuthPARRequestDelete) Exec(ctx context.Context) (int, error) {
	return withHooks(ctx, oprd.sqlExec, oprd.mutation, oprd.hooks)
}

// ExecX is like Exec, but panics if an error occurs.
func (oprd *OAuthPARRequestDelete) ExecX(ctx context.Context) int {
	n, err := oprd.Exec(ctx)
	if err != nil {
		panic(err)
	}
	return n
}

func (oprd *OAuthPARRequestDelete) sqlExec(ctx context.Context) (int, error) {
	_spec := sqlgraph.NewDeleteSpec(oauthparrequest.Table, sqlgraph.NewFieldSpec(oauthparrequest.FieldID, field.TypeInt))
	if ps := oprd.mutation.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	affected, err := sqlgraph.DeleteNodes(ctx, oprd.driver, _spec)
	if err != nil && sqlgraph.IsConstraintError(err) {
		err = &ConstraintError{msg: err.Error(), wrap: err}
	}
	oprd.mutation.done = true
	return affected, err
}

// OAuthPARRequestDeleteOne is the builder for deleting a single OAuthPARRequest entity.
type OAuthPARRequestDeleteOne struct {
	oprd *OAuthPARRequestDelete
}

// Where appends a list predicates to the OAuthPARRequestDelete builder.
func (oprdo *OAuthPARRequestDeleteOne) Where(ps ...predicate.OAuthPARRequest) *OAuthPARRequestDeleteOne {
	oprdo.oprd.mutation.Where(ps...)
	return oprdo
}

// Exec executes the deletion query.
func (oprdo *OAuthPARRequestDeleteOne) Exec(ctx context.Context) error {
	n, err := oprdo.oprd.Exec(ctx)
	switch {
	case err != nil:
		return err
	case n == 0:
		return &NotFoundError{oauthparrequest.Label}
	default:
		return nil
	}
}

// ExecX is like Exec, but panics if an error occurs.
func (oprdo *OAuthPARRequestDeleteOne) ExecX(ctx context.Context) {
	if err := oprdo.Exec(ctx); err != nil {
		panic(err)
	}
}
