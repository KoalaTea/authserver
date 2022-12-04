package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// OIDCSession holds the schema definition for the OIDCSession entity.
type OIDCSession struct {
	ent.Schema
}

// Fields of the OIDCSession.
func (OIDCSession) Fields() []ent.Field {
	return []ent.Field{
		field.String("issuer"),
		field.String("subject"),
		field.JSON("audiences", []string{}),
		field.Time("expires_at"),
		field.Time("issued_at"),
		field.Time("requested_at"),
		field.Time("auth_time"),
	}
}

// Edges of the OIDCSession.
func (OIDCSession) Edges() []ent.Edge {
	return nil
}
