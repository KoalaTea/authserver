// Code generated by ent, DO NOT EDIT.

package ent

import (
	"encoding/json"
	"fmt"
	"strings"

	"entgo.io/ent/dialect/sql"
	"github.com/koalatea/authserver/server/ent/accessrequest"
)

// AccessRequest is the model entity for the AccessRequest schema.
type AccessRequest struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// RequestedScopes holds the value of the "requested_scopes" field.
	RequestedScopes []string `json:"requested_scopes,omitempty"`
	// GrantedScopes holds the value of the "granted_scopes" field.
	GrantedScopes []string `json:"granted_scopes,omitempty"`
	// RequestedAudiences holds the value of the "requested_audiences" field.
	RequestedAudiences []string `json:"requested_audiences,omitempty"`
	// GrantedAudiences holds the value of the "granted_audiences" field.
	GrantedAudiences []string `json:"granted_audiences,omitempty"`
	// Request holds the value of the "request" field.
	Request string `json:"request,omitempty"`
	// Form holds the value of the "form" field.
	Form string `json:"form,omitempty"`
	// Active holds the value of the "active" field.
	Active bool `json:"active,omitempty"`
}

// scanValues returns the types for scanning values from sql.Rows.
func (*AccessRequest) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case accessrequest.FieldRequestedScopes, accessrequest.FieldGrantedScopes, accessrequest.FieldRequestedAudiences, accessrequest.FieldGrantedAudiences:
			values[i] = new([]byte)
		case accessrequest.FieldActive:
			values[i] = new(sql.NullBool)
		case accessrequest.FieldID:
			values[i] = new(sql.NullInt64)
		case accessrequest.FieldRequest, accessrequest.FieldForm:
			values[i] = new(sql.NullString)
		default:
			return nil, fmt.Errorf("unexpected column %q for type AccessRequest", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the AccessRequest fields.
func (ar *AccessRequest) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case accessrequest.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			ar.ID = int(value.Int64)
		case accessrequest.FieldRequestedScopes:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field requested_scopes", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &ar.RequestedScopes); err != nil {
					return fmt.Errorf("unmarshal field requested_scopes: %w", err)
				}
			}
		case accessrequest.FieldGrantedScopes:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field granted_scopes", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &ar.GrantedScopes); err != nil {
					return fmt.Errorf("unmarshal field granted_scopes: %w", err)
				}
			}
		case accessrequest.FieldRequestedAudiences:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field requested_audiences", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &ar.RequestedAudiences); err != nil {
					return fmt.Errorf("unmarshal field requested_audiences: %w", err)
				}
			}
		case accessrequest.FieldGrantedAudiences:
			if value, ok := values[i].(*[]byte); !ok {
				return fmt.Errorf("unexpected type %T for field granted_audiences", values[i])
			} else if value != nil && len(*value) > 0 {
				if err := json.Unmarshal(*value, &ar.GrantedAudiences); err != nil {
					return fmt.Errorf("unmarshal field granted_audiences: %w", err)
				}
			}
		case accessrequest.FieldRequest:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field request", values[i])
			} else if value.Valid {
				ar.Request = value.String
			}
		case accessrequest.FieldForm:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field form", values[i])
			} else if value.Valid {
				ar.Form = value.String
			}
		case accessrequest.FieldActive:
			if value, ok := values[i].(*sql.NullBool); !ok {
				return fmt.Errorf("unexpected type %T for field active", values[i])
			} else if value.Valid {
				ar.Active = value.Bool
			}
		}
	}
	return nil
}

// Update returns a builder for updating this AccessRequest.
// Note that you need to call AccessRequest.Unwrap() before calling this method if this AccessRequest
// was returned from a transaction, and the transaction was committed or rolled back.
func (ar *AccessRequest) Update() *AccessRequestUpdateOne {
	return (&AccessRequestClient{config: ar.config}).UpdateOne(ar)
}

// Unwrap unwraps the AccessRequest entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (ar *AccessRequest) Unwrap() *AccessRequest {
	_tx, ok := ar.config.driver.(*txDriver)
	if !ok {
		panic("ent: AccessRequest is not a transactional entity")
	}
	ar.config.driver = _tx.drv
	return ar
}

// String implements the fmt.Stringer.
func (ar *AccessRequest) String() string {
	var builder strings.Builder
	builder.WriteString("AccessRequest(")
	builder.WriteString(fmt.Sprintf("id=%v, ", ar.ID))
	builder.WriteString("requested_scopes=")
	builder.WriteString(fmt.Sprintf("%v", ar.RequestedScopes))
	builder.WriteString(", ")
	builder.WriteString("granted_scopes=")
	builder.WriteString(fmt.Sprintf("%v", ar.GrantedScopes))
	builder.WriteString(", ")
	builder.WriteString("requested_audiences=")
	builder.WriteString(fmt.Sprintf("%v", ar.RequestedAudiences))
	builder.WriteString(", ")
	builder.WriteString("granted_audiences=")
	builder.WriteString(fmt.Sprintf("%v", ar.GrantedAudiences))
	builder.WriteString(", ")
	builder.WriteString("request=")
	builder.WriteString(ar.Request)
	builder.WriteString(", ")
	builder.WriteString("form=")
	builder.WriteString(ar.Form)
	builder.WriteString(", ")
	builder.WriteString("active=")
	builder.WriteString(fmt.Sprintf("%v", ar.Active))
	builder.WriteByte(')')
	return builder.String()
}

// AccessRequests is a parsable slice of AccessRequest.
type AccessRequests []*AccessRequest

func (ar AccessRequests) config(cfg config) {
	for _i := range ar {
		ar[_i].config = cfg
	}
}