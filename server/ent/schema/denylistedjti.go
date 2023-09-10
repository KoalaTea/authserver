package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// DenyListedJTI holds the schema definition for the DenyListedJTI entity.
type DenyListedJTI struct {
	ent.Schema
}

// Fields of the DenyListedJTI.
func (DenyListedJTI) Fields() []ent.Field {
	return []ent.Field{
		field.String("jti").Unique(),
		field.Time("expiration"),
	}
}

// Edges of the DenyListedJTI.
func (DenyListedJTI) Edges() []ent.Edge {
	return nil
}
