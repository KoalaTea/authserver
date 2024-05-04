package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// AuthCode holds the schema definition for the AuthCode entity.
type AuthCode struct {
	ent.Schema
}

// Fields of the AuthCode.
func (AuthCode) Fields() []ent.Field {
	return []ent.Field{
		field.String("code"),
		field.Bool("active"),
	}
}

// Edges of the AuthCode.
func (AuthCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("session", OAuthSession.Type).Comment("information about the request").Unique().Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
}
