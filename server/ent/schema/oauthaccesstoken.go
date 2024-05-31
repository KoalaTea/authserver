package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// OAuthAccessToken holds the schema definition for the OAuthAccessToken entity.
type OAuthAccessToken struct {
	ent.Schema
}

// Fields of the OAuthAccessToken.
func (OAuthAccessToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("signature"),
	}
}

// Edges of the OAuthAccessToken.
func (OAuthAccessToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("session", OAuthSession.Type).Comment("information about the request").Unique().Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}
