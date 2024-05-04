// Code generated by ent, DO NOT EDIT.

package oauthclient

import (
	"entgo.io/ent/dialect/sql"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		v := make([]any, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.In(s.C(FieldID), v...))
	})
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		v := make([]any, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.NotIn(s.C(FieldID), v...))
	})
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// ClientID applies equality check predicate on the "client_id" field. It's identical to ClientIDEQ.
func ClientID(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldClientID), v))
	})
}

// Secret applies equality check predicate on the "secret" field. It's identical to SecretEQ.
func Secret(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSecret), v))
	})
}

// ClientIDEQ applies the EQ predicate on the "client_id" field.
func ClientIDEQ(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldClientID), v))
	})
}

// ClientIDNEQ applies the NEQ predicate on the "client_id" field.
func ClientIDNEQ(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldClientID), v))
	})
}

// ClientIDIn applies the In predicate on the "client_id" field.
func ClientIDIn(vs ...string) predicate.OAuthClient {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldClientID), v...))
	})
}

// ClientIDNotIn applies the NotIn predicate on the "client_id" field.
func ClientIDNotIn(vs ...string) predicate.OAuthClient {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldClientID), v...))
	})
}

// ClientIDGT applies the GT predicate on the "client_id" field.
func ClientIDGT(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldClientID), v))
	})
}

// ClientIDGTE applies the GTE predicate on the "client_id" field.
func ClientIDGTE(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldClientID), v))
	})
}

// ClientIDLT applies the LT predicate on the "client_id" field.
func ClientIDLT(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldClientID), v))
	})
}

// ClientIDLTE applies the LTE predicate on the "client_id" field.
func ClientIDLTE(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldClientID), v))
	})
}

// ClientIDContains applies the Contains predicate on the "client_id" field.
func ClientIDContains(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldClientID), v))
	})
}

// ClientIDHasPrefix applies the HasPrefix predicate on the "client_id" field.
func ClientIDHasPrefix(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldClientID), v))
	})
}

// ClientIDHasSuffix applies the HasSuffix predicate on the "client_id" field.
func ClientIDHasSuffix(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldClientID), v))
	})
}

// ClientIDEqualFold applies the EqualFold predicate on the "client_id" field.
func ClientIDEqualFold(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldClientID), v))
	})
}

// ClientIDContainsFold applies the ContainsFold predicate on the "client_id" field.
func ClientIDContainsFold(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldClientID), v))
	})
}

// SecretEQ applies the EQ predicate on the "secret" field.
func SecretEQ(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSecret), v))
	})
}

// SecretNEQ applies the NEQ predicate on the "secret" field.
func SecretNEQ(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldSecret), v))
	})
}

// SecretIn applies the In predicate on the "secret" field.
func SecretIn(vs ...string) predicate.OAuthClient {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldSecret), v...))
	})
}

// SecretNotIn applies the NotIn predicate on the "secret" field.
func SecretNotIn(vs ...string) predicate.OAuthClient {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldSecret), v...))
	})
}

// SecretGT applies the GT predicate on the "secret" field.
func SecretGT(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldSecret), v))
	})
}

// SecretGTE applies the GTE predicate on the "secret" field.
func SecretGTE(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldSecret), v))
	})
}

// SecretLT applies the LT predicate on the "secret" field.
func SecretLT(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldSecret), v))
	})
}

// SecretLTE applies the LTE predicate on the "secret" field.
func SecretLTE(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldSecret), v))
	})
}

// SecretContains applies the Contains predicate on the "secret" field.
func SecretContains(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldSecret), v))
	})
}

// SecretHasPrefix applies the HasPrefix predicate on the "secret" field.
func SecretHasPrefix(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldSecret), v))
	})
}

// SecretHasSuffix applies the HasSuffix predicate on the "secret" field.
func SecretHasSuffix(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldSecret), v))
	})
}

// SecretEqualFold applies the EqualFold predicate on the "secret" field.
func SecretEqualFold(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldSecret), v))
	})
}

// SecretContainsFold applies the ContainsFold predicate on the "secret" field.
func SecretContainsFold(v string) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldSecret), v))
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.OAuthClient) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.OAuthClient) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for i, p := range predicates {
			if i > 0 {
				s1.Or()
			}
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Not applies the not operator on the given predicate.
func Not(p predicate.OAuthClient) predicate.OAuthClient {
	return predicate.OAuthClient(func(s *sql.Selector) {
		p(s.Not())
	})
}
