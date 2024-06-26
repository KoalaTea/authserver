// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/koalatea/authserver/server/ent/publicjwk"
)

// PublicJWK is the model entity for the PublicJWK schema.
type PublicJWK struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// Sid holds the value of the "sid" field.
	Sid string `json:"sid,omitempty"`
	// Kid holds the value of the "kid" field.
	Kid string `json:"kid,omitempty"`
	// Key holds the value of the "key" field.
	Key string `json:"key,omitempty"`
	// Issuer holds the value of the "issuer" field.
	Issuer string `json:"issuer,omitempty"`
	// Scopes holds the value of the "scopes" field.
	Scopes       []string `json:"scopes,omitempty"`
	selectValues sql.SelectValues
}

// scanValues returns the types for scanning values from sql.Rows.
func (*PublicJWK) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case publicjwk.FieldScopes:
			values[i] = new([]byte)
		case publicjwk.FieldID:
			values[i] = new(sql.NullInt64)
		case publicjwk.FieldSid, publicjwk.FieldKid, publicjwk.FieldKey, publicjwk.FieldIssuer:
			values[i] = new(sql.NullString)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the PublicJWK fields.
func (pj *PublicJWK) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case publicjwk.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			pj.ID = int(value.Int64)
		case publicjwk.FieldSid:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field sid", values[i])
			} else if value.Valid {
				pj.Sid = value.String
			}
		case publicjwk.FieldKid:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field kid", values[i])
			} else if value.Valid {
				pj.Kid = value.String
			}
		case publicjwk.FieldKey:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field key", values[i])
			} else if value.Valid {
				pj.Key = value.String
			}
		case publicjwk.FieldIssuer:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field issuer", values[i])
			} else if value.Valid {
				pj.Issuer = value.String
			}
		case publicjwk.FieldScopes:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field scopes", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &pj.Scopes); err != nil {
					return fmt.Errorf("unmarshal field scopes: %w", err)
				}
			}
		default:
			pj.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the PublicJWK.
// This includes values selected through modifiers, order, etc.
func (pj *PublicJWK) Value(name string) (ent.Value, error) {
	return pj.selectValues.Get(name)
}

// Update returns a builder for updating this PublicJWK.
// Note that you need to call PublicJWK.Unwrap() before calling this method if this PublicJWK
// was returned from a transaction, and the transaction was committed or rolled back.
func (pj *PublicJWK) Update() *PublicJWKUpdateOne {
	return NewPublicJWKClient(pj.config).UpdateOne(pj)
}

// Unwrap unwraps the PublicJWK entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (pj *PublicJWK) Unwrap() *PublicJWK {
	_tx, ok := pj.config.driver.(*txDriver)
	if !ok {
		panic("ent: PublicJWK is not a transactional entity")
	}
	pj.config.driver = _tx.drv
	return pj
}

// String implements the fmt.Stringer.
func (pj *PublicJWK) String() string {
	var builder strings.Builder
	builder.WriteString("PublicJWK(")
	builder.WriteString(fmt.Sprintf("id=%v, ", pj.ID))
	builder.WriteString("sid=")
	builder.WriteString(pj.Sid)
	builder.WriteString(", ")
	builder.WriteString("kid=")
	builder.WriteString(pj.Kid)
	builder.WriteString(", ")
	builder.WriteString("key=")
	builder.WriteString(pj.Key)
	builder.WriteString(", ")
	builder.WriteString("issuer=")
	builder.WriteString(pj.Issuer)
	builder.WriteString(", ")
	builder.WriteString("scopes=")
	builder.WriteString(fmt.Sprintf("%v", pj.Scopes))
	builder.WriteByte(')')
	return builder.String()
}

// PublicJWKs is a parsable slice of PublicJWK.
type PublicJWKs []*PublicJWK
