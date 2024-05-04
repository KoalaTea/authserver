// Code generated by ent, DO NOT EDIT.

package publicjwk

import (
	"entgo.io/ent/dialect/sql"
	"github.com/koalatea/authserver/server/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id int) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id int) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldID), id))
	})
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id int) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldID), id))
	})
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...int) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		v := make([]any, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.In(s.C(FieldID), v...))
	})
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...int) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		v := make([]any, len(ids))
		for i := range v {
			v[i] = ids[i]
		}
		s.Where(sql.NotIn(s.C(FieldID), v...))
	})
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id int) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldID), id))
	})
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id int) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldID), id))
	})
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id int) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldID), id))
	})
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id int) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldID), id))
	})
}

// Sid applies equality check predicate on the "sid" field. It's identical to SidEQ.
func Sid(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSid), v))
	})
}

// Kid applies equality check predicate on the "kid" field. It's identical to KidEQ.
func Kid(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldKid), v))
	})
}

// Key applies equality check predicate on the "key" field. It's identical to KeyEQ.
func Key(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldKey), v))
	})
}

// Issuer applies equality check predicate on the "issuer" field. It's identical to IssuerEQ.
func Issuer(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldIssuer), v))
	})
}

// SidEQ applies the EQ predicate on the "sid" field.
func SidEQ(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldSid), v))
	})
}

// SidNEQ applies the NEQ predicate on the "sid" field.
func SidNEQ(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldSid), v))
	})
}

// SidIn applies the In predicate on the "sid" field.
func SidIn(vs ...string) predicate.PublicJWK {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldSid), v...))
	})
}

// SidNotIn applies the NotIn predicate on the "sid" field.
func SidNotIn(vs ...string) predicate.PublicJWK {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldSid), v...))
	})
}

// SidGT applies the GT predicate on the "sid" field.
func SidGT(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldSid), v))
	})
}

// SidGTE applies the GTE predicate on the "sid" field.
func SidGTE(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldSid), v))
	})
}

// SidLT applies the LT predicate on the "sid" field.
func SidLT(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldSid), v))
	})
}

// SidLTE applies the LTE predicate on the "sid" field.
func SidLTE(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldSid), v))
	})
}

// SidContains applies the Contains predicate on the "sid" field.
func SidContains(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldSid), v))
	})
}

// SidHasPrefix applies the HasPrefix predicate on the "sid" field.
func SidHasPrefix(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldSid), v))
	})
}

// SidHasSuffix applies the HasSuffix predicate on the "sid" field.
func SidHasSuffix(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldSid), v))
	})
}

// SidEqualFold applies the EqualFold predicate on the "sid" field.
func SidEqualFold(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldSid), v))
	})
}

// SidContainsFold applies the ContainsFold predicate on the "sid" field.
func SidContainsFold(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldSid), v))
	})
}

// KidEQ applies the EQ predicate on the "kid" field.
func KidEQ(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldKid), v))
	})
}

// KidNEQ applies the NEQ predicate on the "kid" field.
func KidNEQ(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldKid), v))
	})
}

// KidIn applies the In predicate on the "kid" field.
func KidIn(vs ...string) predicate.PublicJWK {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldKid), v...))
	})
}

// KidNotIn applies the NotIn predicate on the "kid" field.
func KidNotIn(vs ...string) predicate.PublicJWK {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldKid), v...))
	})
}

// KidGT applies the GT predicate on the "kid" field.
func KidGT(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldKid), v))
	})
}

// KidGTE applies the GTE predicate on the "kid" field.
func KidGTE(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldKid), v))
	})
}

// KidLT applies the LT predicate on the "kid" field.
func KidLT(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldKid), v))
	})
}

// KidLTE applies the LTE predicate on the "kid" field.
func KidLTE(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldKid), v))
	})
}

// KidContains applies the Contains predicate on the "kid" field.
func KidContains(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldKid), v))
	})
}

// KidHasPrefix applies the HasPrefix predicate on the "kid" field.
func KidHasPrefix(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldKid), v))
	})
}

// KidHasSuffix applies the HasSuffix predicate on the "kid" field.
func KidHasSuffix(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldKid), v))
	})
}

// KidEqualFold applies the EqualFold predicate on the "kid" field.
func KidEqualFold(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldKid), v))
	})
}

// KidContainsFold applies the ContainsFold predicate on the "kid" field.
func KidContainsFold(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldKid), v))
	})
}

// KeyEQ applies the EQ predicate on the "key" field.
func KeyEQ(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldKey), v))
	})
}

// KeyNEQ applies the NEQ predicate on the "key" field.
func KeyNEQ(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldKey), v))
	})
}

// KeyIn applies the In predicate on the "key" field.
func KeyIn(vs ...string) predicate.PublicJWK {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldKey), v...))
	})
}

// KeyNotIn applies the NotIn predicate on the "key" field.
func KeyNotIn(vs ...string) predicate.PublicJWK {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldKey), v...))
	})
}

// KeyGT applies the GT predicate on the "key" field.
func KeyGT(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldKey), v))
	})
}

// KeyGTE applies the GTE predicate on the "key" field.
func KeyGTE(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldKey), v))
	})
}

// KeyLT applies the LT predicate on the "key" field.
func KeyLT(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldKey), v))
	})
}

// KeyLTE applies the LTE predicate on the "key" field.
func KeyLTE(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldKey), v))
	})
}

// KeyContains applies the Contains predicate on the "key" field.
func KeyContains(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldKey), v))
	})
}

// KeyHasPrefix applies the HasPrefix predicate on the "key" field.
func KeyHasPrefix(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldKey), v))
	})
}

// KeyHasSuffix applies the HasSuffix predicate on the "key" field.
func KeyHasSuffix(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldKey), v))
	})
}

// KeyEqualFold applies the EqualFold predicate on the "key" field.
func KeyEqualFold(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldKey), v))
	})
}

// KeyContainsFold applies the ContainsFold predicate on the "key" field.
func KeyContainsFold(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldKey), v))
	})
}

// IssuerEQ applies the EQ predicate on the "issuer" field.
func IssuerEQ(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EQ(s.C(FieldIssuer), v))
	})
}

// IssuerNEQ applies the NEQ predicate on the "issuer" field.
func IssuerNEQ(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.NEQ(s.C(FieldIssuer), v))
	})
}

// IssuerIn applies the In predicate on the "issuer" field.
func IssuerIn(vs ...string) predicate.PublicJWK {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.In(s.C(FieldIssuer), v...))
	})
}

// IssuerNotIn applies the NotIn predicate on the "issuer" field.
func IssuerNotIn(vs ...string) predicate.PublicJWK {
	v := make([]any, len(vs))
	for i := range v {
		v[i] = vs[i]
	}
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.NotIn(s.C(FieldIssuer), v...))
	})
}

// IssuerGT applies the GT predicate on the "issuer" field.
func IssuerGT(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GT(s.C(FieldIssuer), v))
	})
}

// IssuerGTE applies the GTE predicate on the "issuer" field.
func IssuerGTE(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.GTE(s.C(FieldIssuer), v))
	})
}

// IssuerLT applies the LT predicate on the "issuer" field.
func IssuerLT(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LT(s.C(FieldIssuer), v))
	})
}

// IssuerLTE applies the LTE predicate on the "issuer" field.
func IssuerLTE(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.LTE(s.C(FieldIssuer), v))
	})
}

// IssuerContains applies the Contains predicate on the "issuer" field.
func IssuerContains(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.Contains(s.C(FieldIssuer), v))
	})
}

// IssuerHasPrefix applies the HasPrefix predicate on the "issuer" field.
func IssuerHasPrefix(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.HasPrefix(s.C(FieldIssuer), v))
	})
}

// IssuerHasSuffix applies the HasSuffix predicate on the "issuer" field.
func IssuerHasSuffix(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.HasSuffix(s.C(FieldIssuer), v))
	})
}

// IssuerEqualFold applies the EqualFold predicate on the "issuer" field.
func IssuerEqualFold(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.EqualFold(s.C(FieldIssuer), v))
	})
}

// IssuerContainsFold applies the ContainsFold predicate on the "issuer" field.
func IssuerContainsFold(v string) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s.Where(sql.ContainsFold(s.C(FieldIssuer), v))
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.PublicJWK) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.PublicJWK) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
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
func Not(p predicate.PublicJWK) predicate.PublicJWK {
	return predicate.PublicJWK(func(s *sql.Selector) {
		p(s.Not())
	})
}
