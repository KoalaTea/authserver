package schema

import "entgo.io/ent"

// PublicJWKSet holds the schema definition for the PublicJWKSet entity.
type PublicJWKSet struct {
	ent.Schema
}

// Fields of the PublicJWKSet.
func (PublicJWKSet) Fields() []ent.Field {
	return nil
}

// Edges of the PublicJWKSet.
func (PublicJWKSet) Edges() []ent.Edge {
	return nil
}
