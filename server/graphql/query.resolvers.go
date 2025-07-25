package graphql

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.43

import (
	"context"
	"fmt"

	"github.com/koalatea/authserver/server/auth"
	"github.com/koalatea/authserver/server/ent"
)

// Me is the resolver for the me field.
func (r *queryResolver) Me(ctx context.Context) (*ent.User, error) {
	if authUser := auth.UserFromContext(ctx); authUser != nil {
		return authUser, nil
	}
	return nil, fmt.Errorf("no authenticated user present in request context")
}
