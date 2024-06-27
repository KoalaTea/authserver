// Code generated by ent, DO NOT EDIT.

package cert

import (
	"entgo.io/ent/dialect/sql"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.Cert {
	return predicate.Cert(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.Cert {
	return predicate.Cert(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.Cert {
	return predicate.Cert(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.Cert {
	return predicate.Cert(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.Cert {
	return predicate.Cert(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.Cert {
	return predicate.Cert(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.Cert {
	return predicate.Cert(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.Cert {
	return predicate.Cert(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.Cert {
	return predicate.Cert(sql.FieldLTE(FieldID, id))
}

// Revoked applies equality check predicate on the "revoked" field. It's identical to RevokedEQ.
func Revoked(v bool) predicate.Cert {
	return predicate.Cert(sql.FieldEQ(FieldRevoked, v))
}

// Pem applies equality check predicate on the "pem" field. It's identical to PemEQ.
func Pem(v string) predicate.Cert {
	return predicate.Cert(sql.FieldEQ(FieldPem, v))
}

// SerialNumber applies equality check predicate on the "serial_number" field. It's identical to SerialNumberEQ.
func SerialNumber(v int64) predicate.Cert {
	return predicate.Cert(sql.FieldEQ(FieldSerialNumber, v))
}

// RevokedEQ applies the EQ predicate on the "revoked" field.
func RevokedEQ(v bool) predicate.Cert {
	return predicate.Cert(sql.FieldEQ(FieldRevoked, v))
}

// RevokedNEQ applies the NEQ predicate on the "revoked" field.
func RevokedNEQ(v bool) predicate.Cert {
	return predicate.Cert(sql.FieldNEQ(FieldRevoked, v))
}

// PemEQ applies the EQ predicate on the "pem" field.
func PemEQ(v string) predicate.Cert {
	return predicate.Cert(sql.FieldEQ(FieldPem, v))
}

// PemNEQ applies the NEQ predicate on the "pem" field.
func PemNEQ(v string) predicate.Cert {
	return predicate.Cert(sql.FieldNEQ(FieldPem, v))
}

// PemIn applies the In predicate on the "pem" field.
func PemIn(vs ...string) predicate.Cert {
	return predicate.Cert(sql.FieldIn(FieldPem, vs...))
}

// PemNotIn applies the NotIn predicate on the "pem" field.
func PemNotIn(vs ...string) predicate.Cert {
	return predicate.Cert(sql.FieldNotIn(FieldPem, vs...))
}

// PemGT applies the GT predicate on the "pem" field.
func PemGT(v string) predicate.Cert {
	return predicate.Cert(sql.FieldGT(FieldPem, v))
}

// PemGTE applies the GTE predicate on the "pem" field.
func PemGTE(v string) predicate.Cert {
	return predicate.Cert(sql.FieldGTE(FieldPem, v))
}

// PemLT applies the LT predicate on the "pem" field.
func PemLT(v string) predicate.Cert {
	return predicate.Cert(sql.FieldLT(FieldPem, v))
}

// PemLTE applies the LTE predicate on the "pem" field.
func PemLTE(v string) predicate.Cert {
	return predicate.Cert(sql.FieldLTE(FieldPem, v))
}

// PemContains applies the Contains predicate on the "pem" field.
func PemContains(v string) predicate.Cert {
	return predicate.Cert(sql.FieldContains(FieldPem, v))
}

// PemHasPrefix applies the HasPrefix predicate on the "pem" field.
func PemHasPrefix(v string) predicate.Cert {
	return predicate.Cert(sql.FieldHasPrefix(FieldPem, v))
}

// PemHasSuffix applies the HasSuffix predicate on the "pem" field.
func PemHasSuffix(v string) predicate.Cert {
	return predicate.Cert(sql.FieldHasSuffix(FieldPem, v))
}

// PemEqualFold applies the EqualFold predicate on the "pem" field.
func PemEqualFold(v string) predicate.Cert {
	return predicate.Cert(sql.FieldEqualFold(FieldPem, v))
}

// PemContainsFold applies the ContainsFold predicate on the "pem" field.
func PemContainsFold(v string) predicate.Cert {
	return predicate.Cert(sql.FieldContainsFold(FieldPem, v))
}

// SerialNumberEQ applies the EQ predicate on the "serial_number" field.
func SerialNumberEQ(v int64) predicate.Cert {
	return predicate.Cert(sql.FieldEQ(FieldSerialNumber, v))
}

// SerialNumberNEQ applies the NEQ predicate on the "serial_number" field.
func SerialNumberNEQ(v int64) predicate.Cert {
	return predicate.Cert(sql.FieldNEQ(FieldSerialNumber, v))
}

// SerialNumberIn applies the In predicate on the "serial_number" field.
func SerialNumberIn(vs ...int64) predicate.Cert {
	return predicate.Cert(sql.FieldIn(FieldSerialNumber, vs...))
}

// SerialNumberNotIn applies the NotIn predicate on the "serial_number" field.
func SerialNumberNotIn(vs ...int64) predicate.Cert {
	return predicate.Cert(sql.FieldNotIn(FieldSerialNumber, vs...))
}

// SerialNumberGT applies the GT predicate on the "serial_number" field.
func SerialNumberGT(v int64) predicate.Cert {
	return predicate.Cert(sql.FieldGT(FieldSerialNumber, v))
}

// SerialNumberGTE applies the GTE predicate on the "serial_number" field.
func SerialNumberGTE(v int64) predicate.Cert {
	return predicate.Cert(sql.FieldGTE(FieldSerialNumber, v))
}

// SerialNumberLT applies the LT predicate on the "serial_number" field.
func SerialNumberLT(v int64) predicate.Cert {
	return predicate.Cert(sql.FieldLT(FieldSerialNumber, v))
}

// SerialNumberLTE applies the LTE predicate on the "serial_number" field.
func SerialNumberLTE(v int64) predicate.Cert {
	return predicate.Cert(sql.FieldLTE(FieldSerialNumber, v))
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Cert) predicate.Cert {
	return predicate.Cert(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Cert) predicate.Cert {
	return predicate.Cert(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.Cert) predicate.Cert {
	return predicate.Cert(sql.NotPredicates(p))
}
