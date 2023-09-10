package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// User holds the schema definition for the User entity.
type OIDCAuthCode struct {
	ent.Schema
}

// Fields of the User.
func (OIDCAuthCode) Fields() []ent.Field {
	return []ent.Field{
		field.String("authorization_code"),
	}
}

// Edges of the User.
func (OIDCAuthCode) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("session", OAuthSession.Type).Comment("information about the request").Unique().Annotations(entsql.Annotation{OnDelete: entsql.Cascade}),
	}
	// 	edge.To("user", User.Type).Comment("The user who this authorization code belongs to"),
	// }
}
