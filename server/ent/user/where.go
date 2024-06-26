// Code generated by ent, DO NOT EDIT.

package user

import (
	"entgo.io/ent/dialect/sql"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.User {
	return predicate.User(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.User {
	return predicate.User(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.User {
	return predicate.User(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.User {
	return predicate.User(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.User {
	return predicate.User(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.User {
	return predicate.User(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.User {
	return predicate.User(sql.FieldLTE(FieldID, id))
}

// Name applies equality check predicate on the "Name" field. It's identical to NameEQ.
func Name(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldName, v))
}

// OAuthID applies equality check predicate on the "OAuthID" field. It's identical to OAuthIDEQ.
func OAuthID(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldOAuthID, v))
}

// SessionToken applies equality check predicate on the "SessionToken" field. It's identical to SessionTokenEQ.
func SessionToken(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldSessionToken, v))
}

// IsActivated applies equality check predicate on the "IsActivated" field. It's identical to IsActivatedEQ.
func IsActivated(v bool) predicate.User {
	return predicate.User(sql.FieldEQ(FieldIsActivated, v))
}

// NameEQ applies the EQ predicate on the "Name" field.
func NameEQ(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldName, v))
}

// NameNEQ applies the NEQ predicate on the "Name" field.
func NameNEQ(v string) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldName, v))
}

// NameIn applies the In predicate on the "Name" field.
func NameIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldIn(FieldName, vs...))
}

// NameNotIn applies the NotIn predicate on the "Name" field.
func NameNotIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldName, vs...))
}

// NameGT applies the GT predicate on the "Name" field.
func NameGT(v string) predicate.User {
	return predicate.User(sql.FieldGT(FieldName, v))
}

// NameGTE applies the GTE predicate on the "Name" field.
func NameGTE(v string) predicate.User {
	return predicate.User(sql.FieldGTE(FieldName, v))
}

// NameLT applies the LT predicate on the "Name" field.
func NameLT(v string) predicate.User {
	return predicate.User(sql.FieldLT(FieldName, v))
}

// NameLTE applies the LTE predicate on the "Name" field.
func NameLTE(v string) predicate.User {
	return predicate.User(sql.FieldLTE(FieldName, v))
}

// NameContains applies the Contains predicate on the "Name" field.
func NameContains(v string) predicate.User {
	return predicate.User(sql.FieldContains(FieldName, v))
}

// NameHasPrefix applies the HasPrefix predicate on the "Name" field.
func NameHasPrefix(v string) predicate.User {
	return predicate.User(sql.FieldHasPrefix(FieldName, v))
}

// NameHasSuffix applies the HasSuffix predicate on the "Name" field.
func NameHasSuffix(v string) predicate.User {
	return predicate.User(sql.FieldHasSuffix(FieldName, v))
}

// NameEqualFold applies the EqualFold predicate on the "Name" field.
func NameEqualFold(v string) predicate.User {
	return predicate.User(sql.FieldEqualFold(FieldName, v))
}

// NameContainsFold applies the ContainsFold predicate on the "Name" field.
func NameContainsFold(v string) predicate.User {
	return predicate.User(sql.FieldContainsFold(FieldName, v))
}

// OAuthIDEQ applies the EQ predicate on the "OAuthID" field.
func OAuthIDEQ(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldOAuthID, v))
}

// OAuthIDNEQ applies the NEQ predicate on the "OAuthID" field.
func OAuthIDNEQ(v string) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldOAuthID, v))
}

// OAuthIDIn applies the In predicate on the "OAuthID" field.
func OAuthIDIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldIn(FieldOAuthID, vs...))
}

// OAuthIDNotIn applies the NotIn predicate on the "OAuthID" field.
func OAuthIDNotIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldOAuthID, vs...))
}

// OAuthIDGT applies the GT predicate on the "OAuthID" field.
func OAuthIDGT(v string) predicate.User {
	return predicate.User(sql.FieldGT(FieldOAuthID, v))
}

// OAuthIDGTE applies the GTE predicate on the "OAuthID" field.
func OAuthIDGTE(v string) predicate.User {
	return predicate.User(sql.FieldGTE(FieldOAuthID, v))
}

// OAuthIDLT applies the LT predicate on the "OAuthID" field.
func OAuthIDLT(v string) predicate.User {
	return predicate.User(sql.FieldLT(FieldOAuthID, v))
}

// OAuthIDLTE applies the LTE predicate on the "OAuthID" field.
func OAuthIDLTE(v string) predicate.User {
	return predicate.User(sql.FieldLTE(FieldOAuthID, v))
}

// OAuthIDContains applies the Contains predicate on the "OAuthID" field.
func OAuthIDContains(v string) predicate.User {
	return predicate.User(sql.FieldContains(FieldOAuthID, v))
}

// OAuthIDHasPrefix applies the HasPrefix predicate on the "OAuthID" field.
func OAuthIDHasPrefix(v string) predicate.User {
	return predicate.User(sql.FieldHasPrefix(FieldOAuthID, v))
}

// OAuthIDHasSuffix applies the HasSuffix predicate on the "OAuthID" field.
func OAuthIDHasSuffix(v string) predicate.User {
	return predicate.User(sql.FieldHasSuffix(FieldOAuthID, v))
}

// OAuthIDEqualFold applies the EqualFold predicate on the "OAuthID" field.
func OAuthIDEqualFold(v string) predicate.User {
	return predicate.User(sql.FieldEqualFold(FieldOAuthID, v))
}

// OAuthIDContainsFold applies the ContainsFold predicate on the "OAuthID" field.
func OAuthIDContainsFold(v string) predicate.User {
	return predicate.User(sql.FieldContainsFold(FieldOAuthID, v))
}

// SessionTokenEQ applies the EQ predicate on the "SessionToken" field.
func SessionTokenEQ(v string) predicate.User {
	return predicate.User(sql.FieldEQ(FieldSessionToken, v))
}

// SessionTokenNEQ applies the NEQ predicate on the "SessionToken" field.
func SessionTokenNEQ(v string) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldSessionToken, v))
}

// SessionTokenIn applies the In predicate on the "SessionToken" field.
func SessionTokenIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldIn(FieldSessionToken, vs...))
}

// SessionTokenNotIn applies the NotIn predicate on the "SessionToken" field.
func SessionTokenNotIn(vs ...string) predicate.User {
	return predicate.User(sql.FieldNotIn(FieldSessionToken, vs...))
}

// SessionTokenGT applies the GT predicate on the "SessionToken" field.
func SessionTokenGT(v string) predicate.User {
	return predicate.User(sql.FieldGT(FieldSessionToken, v))
}

// SessionTokenGTE applies the GTE predicate on the "SessionToken" field.
func SessionTokenGTE(v string) predicate.User {
	return predicate.User(sql.FieldGTE(FieldSessionToken, v))
}

// SessionTokenLT applies the LT predicate on the "SessionToken" field.
func SessionTokenLT(v string) predicate.User {
	return predicate.User(sql.FieldLT(FieldSessionToken, v))
}

// SessionTokenLTE applies the LTE predicate on the "SessionToken" field.
func SessionTokenLTE(v string) predicate.User {
	return predicate.User(sql.FieldLTE(FieldSessionToken, v))
}

// SessionTokenContains applies the Contains predicate on the "SessionToken" field.
func SessionTokenContains(v string) predicate.User {
	return predicate.User(sql.FieldContains(FieldSessionToken, v))
}

// SessionTokenHasPrefix applies the HasPrefix predicate on the "SessionToken" field.
func SessionTokenHasPrefix(v string) predicate.User {
	return predicate.User(sql.FieldHasPrefix(FieldSessionToken, v))
}

// SessionTokenHasSuffix applies the HasSuffix predicate on the "SessionToken" field.
func SessionTokenHasSuffix(v string) predicate.User {
	return predicate.User(sql.FieldHasSuffix(FieldSessionToken, v))
}

// SessionTokenEqualFold applies the EqualFold predicate on the "SessionToken" field.
func SessionTokenEqualFold(v string) predicate.User {
	return predicate.User(sql.FieldEqualFold(FieldSessionToken, v))
}

// SessionTokenContainsFold applies the ContainsFold predicate on the "SessionToken" field.
func SessionTokenContainsFold(v string) predicate.User {
	return predicate.User(sql.FieldContainsFold(FieldSessionToken, v))
}

// IsActivatedEQ applies the EQ predicate on the "IsActivated" field.
func IsActivatedEQ(v bool) predicate.User {
	return predicate.User(sql.FieldEQ(FieldIsActivated, v))
}

// IsActivatedNEQ applies the NEQ predicate on the "IsActivated" field.
func IsActivatedNEQ(v bool) predicate.User {
	return predicate.User(sql.FieldNEQ(FieldIsActivated, v))
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.User) predicate.User {
	return predicate.User(sql.AndPredicates(predicates...))
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.User) predicate.User {
	return predicate.User(sql.OrPredicates(predicates...))
}

// Not applies the not operator on the given predicate.
func Not(p predicate.User) predicate.User {
	return predicate.User(sql.NotPredicates(p))
}
