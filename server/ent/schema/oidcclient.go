package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// OIDCClient holds the schema definition for the OIDCClient entity.
type OIDCClient struct {
	ent.Schema
}

// Fields of the OIDCClient.
func (OIDCClient) Fields() []ent.Field {
	return []ent.Field{
		field.String("client_id"),
		field.String("secret"),
		field.JSON("redirect_uris", []string{}),
		field.JSON("response_types", []string{}),
		field.JSON("grant_types", []string{}),
		field.JSON("scopes", []string{}),
	}
}

// Edges of the OIDCClient.
func (OIDCClient) Edges() []ent.Edge {
	return nil
}
