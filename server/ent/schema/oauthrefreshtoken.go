package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// OAuthRefreshToken holds the schema definition for the OAuthRefreshToken entity.
type OAuthRefreshToken struct {
	ent.Schema
}

// Fields of the OAuthRefreshToken.
func (OAuthRefreshToken) Fields() []ent.Field {
	return []ent.Field{
		field.String("signature"),
	}

}

// Edges of the OAuthRefreshToken.
func (OAuthRefreshToken) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("session", OAuthSession.Type).Comment("information about the request").Unique().Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}
