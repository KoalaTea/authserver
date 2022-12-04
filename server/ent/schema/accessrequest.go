package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// AccessRequest holds the schema definition for the AccessRequest entity.
type AccessRequest struct {
	ent.Schema
}

// Fields of the AccessRequest.
func (AccessRequest) Fields() []ent.Field {
	return []ent.Field{
		field.JSON("requested_scopes", []string{}),
		field.JSON("granted_scopes", []string{}),
		field.JSON("requested_audiences", []string{}),
		field.JSON("granted_audiences", []string{}),
		field.String("request"),
		field.String("form"),
		field.Bool("active"),
		field.String("request_id"),
	}
}

// Edges of the AccessRequest.
func (AccessRequest) Edges() []ent.Edge {
	return nil
}
