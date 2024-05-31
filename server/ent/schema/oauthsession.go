package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// OAuthSession holds the schema definition for the OAuthSession entity.
type OAuthSession struct {
	ent.Schema
}

// Fields of the OAuthSession.
func (OAuthSession) Fields() []ent.Field {
	return []ent.Field{
		field.String("issuer"),
		field.String("subject"),
		field.JSON("audiences", []string{}),
		field.Time("expires_at"),
		field.Time("issued_at"),
		field.Time("requested_at"),
		field.Time("auth_time"),
		field.JSON("requested_scopes", []string{}),
		field.JSON("granted_scopes", []string{}),
		field.JSON("requested_audiences", []string{}),
		field.JSON("granted_audiences", []string{}),
		field.String("request"),
		field.String("form"),
	}
}

// Edges of the OAuthSession.
func (OAuthSession) Edges() []ent.Edge {
	return nil
}
