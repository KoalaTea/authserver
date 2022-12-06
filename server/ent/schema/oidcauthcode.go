package schema

import (
	"entgo.io/ent"
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
		edge.To("access_request", AccessRequest.Type).Comment("information about the request").Unique(),
		edge.To("session", OIDCSession.Type).Comment("information about the request").Unique(),
	}
	// 	edge.To("user", User.Type).Comment("The user who this authorization code belongs to"),
	// }
}
