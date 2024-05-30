package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// OAuthClient holds the schema definition for the OAuthClient entity.
type OAuthClient struct {
	ent.Schema
}

// Fields of the OAuthClient.
func (OAuthClient) Fields() []ent.Field {
	return []ent.Field{
		field.String("client_id"),
		field.String("secret"),
		field.JSON("redirect_uris", []string{}),
		field.JSON("response_types", []string{}),
		field.JSON("grant_types", []string{}),
		field.JSON("scopes", []string{}),
	}
}

// Edges of the OAuthClient.
func (OAuthClient) Edges() []ent.Edge {
	return nil
}
