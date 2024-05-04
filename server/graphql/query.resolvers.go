package graphql

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.21 DO NOT EDIT.

import (
	"context"

	"github.com/koalatea/authserver/server/ent"
	"github.com/koalatea/authserver/server/graphql/generated"
)

// Node is the resolver for the node field.
func (r *queryResolver) Node(ctx context.Context, id int) (ent.Noder, error) {
	ctx, span := tracer.Start(ctx, "Node")
	defer span.End()
	return r.client.Noder(ctx, id)
}

// Nodes is the resolver for the nodes field.
func (r *queryResolver) Nodes(ctx context.Context, ids []int) ([]ent.Noder, error) {
	ctx, span := tracer.Start(ctx, "Nodes")
	defer span.End()
	return r.client.Noders(ctx, ids)
}

// Users is the resolver for the users field.
func (r *queryResolver) Users(ctx context.Context) ([]*ent.User, error) {
	ctx, span := tracer.Start(ctx, "Users")
	defer span.End()
	return r.client.User.Query().All(ctx)
}

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type queryResolver struct{ *Resolver }
