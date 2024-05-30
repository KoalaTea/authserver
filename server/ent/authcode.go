// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"github.com/koalatea/authserver/server/ent/authcode"
	"github.com/koalatea/authserver/server/ent/oauthsession"
)

// AuthCode is the model entity for the AuthCode schema.
type AuthCode struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// Code holds the value of the "code" field.
	Code string `json:"code,omitempty"`
	// Active holds the value of the "active" field.
	Active bool `json:"active,omitempty"`
	// Edges holds the relations/edges for other nodes in the graph.
	// The values are being populated by the AuthCodeQuery when eager-loading is set.
	Edges             AuthCodeEdges `json:"edges"`
	auth_code_session *int
	selectValues      sql.SelectValues
}

// AuthCodeEdges holds the relations/edges for other nodes in the graph.
type AuthCodeEdges struct {
	// information about the request
	Session *OAuthSession `json:"session,omitempty"`
	// loadedTypes holds the information for reporting if a
	// type was loaded (or requested) in eager-loading or not.
	loadedTypes [1]bool
	// totalCount holds the count of the edges above.
	totalCount [1]map[string]int
}

// SessionOrErr returns the Session value or an error if the edge
// was not loaded in eager-loading, or loaded but was not found.
func (e AuthCodeEdges) SessionOrErr() (*OAuthSession, error) {
	if e.Session != nil {
		return e.Session, nil
	} else if e.loadedTypes[0] {
		return nil, &NotFoundError{label: oauthsession.Label}
	}
	return nil, &NotLoadedError{edge: "session"}
}

// scanValues returns the types for scanning values from sql.Rows.
func (*AuthCode) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case authcode.FieldActive:
			values[i] = new(sql.NullBool)
		case authcode.FieldID:
			values[i] = new(sql.NullInt64)
		case authcode.FieldCode:
			values[i] = new(sql.NullString)
		case authcode.ForeignKeys[0]: // auth_code_session
			values[i] = new(sql.NullInt64)
		default:
			values[i] = new(sql.UnknownType)
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the AuthCode fields.
func (ac *AuthCode) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case authcode.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			ac.ID = int(value.Int64)
		case authcode.FieldCode:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field code", values[i])
			} else if value.Valid {
				ac.Code = value.String
			}
		case authcode.FieldActive:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field active", values[i])
			} else if value.Valid {
				ac.Active = value.Bool
			}
		case authcode.ForeignKeys[0]:
			if value, ok := values[i].(*sql.NullInt64); !ok {
				return fmt.Errorf("unexpected type %T for edge-field auth_code_session", value)
			} else if value.Valid {
				ac.auth_code_session = new(int)
				*ac.auth_code_session = int(value.Int64)
			}
		default:
			ac.selectValues.Set(columns[i], values[i])
		}
	}
	return nil
}

// Value returns the ent.Value that was dynamically selected and assigned to the AuthCode.
// This includes values selected through modifiers, order, etc.
func (ac *AuthCode) Value(name string) (ent.Value, error) {
	return ac.selectValues.Get(name)
}

// QuerySession queries the "session" edge of the AuthCode entity.
func (ac *AuthCode) QuerySession() *OAuthSessionQuery {
	return NewAuthCodeClient(ac.config).QuerySession(ac)
}

// Update returns a builder for updating this AuthCode.
// Note that you need to call AuthCode.Unwrap() before calling this method if this AuthCode
// was returned from a transaction, and the transaction was committed or rolled back.
func (ac *AuthCode) Update() *AuthCodeUpdateOne {
	return NewAuthCodeClient(ac.config).UpdateOne(ac)
}

// Unwrap unwraps the AuthCode entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ac *AuthCode) Unwrap() *AuthCode {
	_tx, ok := ac.config.driver.(*txDriver)
	if !ok {
		panic("ent: AuthCode is not a transactional entity")
	}
	ac.config.driver = _tx.drv
	return ac
}

// String implements the fmt.Stringer.
func (ac *AuthCode) String() string {
	var builder strings.Builder
	builder.WriteString("AuthCode(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ac.ID))
	builder.WriteString("code=")
	builder.WriteString(ac.Code)
	builder.WriteString(", ")
	builder.WriteString("active=")
	builder.WriteString(fmt.Sprintf("%v", ac.Active))
	builder.WriteByte(')')
	return builder.String()
}

// AuthCodes is a parsable slice of AuthCode.
type AuthCodes []*AuthCode
