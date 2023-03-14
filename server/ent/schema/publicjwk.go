package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// PublicJWK holds the schema definition for the PublicJWK entity.
type PublicJWK struct {
	ent.Schema
}

// Fields of the PublicJWK.
func (PublicJWK) Fields() []ent.Field {
	return []ent.Field{
		field.String("sid"),
		field.String("kid"),
		field.String("key"),
		field.String("issuer"),
		field.JSON("scopes", []string{}), // might be seperate
	}
}

// Edges of the PublicJWK.
func (PublicJWK) Edges() []ent.Edge {
	return nil
}
