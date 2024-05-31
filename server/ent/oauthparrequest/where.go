// Code generated by ent, DO NOT EDIT.

package oauthparrequest

import (
	"entgo.io/ent/dialect/sql"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldLTE(FieldID, id))
}

// Request applies equality check predicate on the "request" field. It's identical to RequestEQ.
func Request(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldEQ(FieldRequest, v))
}

// RequestEQ applies the EQ predicate on the "request" field.
func RequestEQ(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldEQ(FieldRequest, v))
}

// RequestNEQ applies the NEQ predicate on the "request" field.
func RequestNEQ(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldNEQ(FieldRequest, v))
}

// RequestIn applies the In predicate on the "request" field.
func RequestIn(vs ...string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldIn(FieldRequest, vs...))
}

// RequestNotIn applies the NotIn predicate on the "request" field.
func RequestNotIn(vs ...string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldNotIn(FieldRequest, vs...))
}

// RequestGT applies the GT predicate on the "request" field.
func RequestGT(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldGT(FieldRequest, v))
}

// RequestGTE applies the GTE predicate on the "request" field.
func RequestGTE(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldGTE(FieldRequest, v))
}

// RequestLT applies the LT predicate on the "request" field.
func RequestLT(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldLT(FieldRequest, v))
}

// RequestLTE applies the LTE predicate on the "request" field.
func RequestLTE(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldLTE(FieldRequest, v))
}

// RequestContains applies the Contains predicate on the "request" field.
func RequestContains(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldContains(FieldRequest, v))
}

// RequestHasPrefix applies the HasPrefix predicate on the "request" field.
func RequestHasPrefix(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldHasPrefix(FieldRequest, v))
}

// RequestHasSuffix applies the HasSuffix predicate on the "request" field.
func RequestHasSuffix(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldHasSuffix(FieldRequest, v))
}

// RequestEqualFold applies the EqualFold predicate on the "request" field.
func RequestEqualFold(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldEqualFold(FieldRequest, v))
}

// RequestContainsFold applies the ContainsFold predicate on the "request" field.
func RequestContainsFold(v string) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.FieldContainsFold(FieldRequest, v))
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.OAuthPARRequest) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.OAuthPARRequest) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.OAuthPARRequest) predicate.OAuthPARRequest {
	return predicate.OAuthPARRequest(sql.NotPredicates(p))
}
