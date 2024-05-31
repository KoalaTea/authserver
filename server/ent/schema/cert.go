package schema

import "entgo.io/ent"

// Cert holds the schema definition for the Cert entity.
type Cert struct {
	ent.Schema
}

// Fields of the Cert.
func (Cert) Fields() []ent.Field {
	return nil
}

// Edges of the Cert.
func (Cert) Edges() []ent.Edge {
	return nil
}
