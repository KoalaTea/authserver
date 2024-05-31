package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// OAuthPAR holds the schema definition for the OAuthPAR entity.
type OAuthPARRequest struct {
	ent.Schema
}

// Fields of the OAuthPAR.
func (OAuthPARRequest) Fields() []ent.Field {
	return []ent.Field{
		field.String("request"),
	}
}

// Edges of the OAuthPAR.
func (OAuthPARRequest) Edges() []ent.Edge {
	return nil
}
