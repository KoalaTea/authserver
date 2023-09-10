package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// PKCE holds the schema definition for the PKCE entity.
type PKCE struct {
	ent.Schema
}

// Fields of the PKCE.
func (PKCE) Fields() []ent.Field {
	return []ent.Field{
		field.String("code"),
	}
}

// Edges of the PKCE.
func (PKCE) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("session", OAuthSession.Type).Comment("information about the request").Unique().Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}
