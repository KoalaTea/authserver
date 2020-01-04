// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"errors"

	"github.com/facebookincubator/ent/dialect/sql/sqlgraph"
	"github.com/facebookincubator/ent/schema/field"
	"github.com/koalatea/authserver/ent/user"
)

// UserCreate is the builder for creating a User entity.
type UserCreate struct {
	config
	username *string
	password *string
}

// SetUsername sets the username field.
func (uc *UserCreate) SetUsername(s string) *UserCreate {
	uc.username = &s
	return uc
}

// SetPassword sets the password field.
func (uc *UserCreate) SetPassword(s string) *UserCreate {
	uc.password = &s
	return uc
}

// Save creates the User in the database.
func (uc *UserCreate) Save(ctx context.Context) (*User, error) {
	if uc.username == nil {
		return nil, errors.New("ent: missing required field \"username\"")
	}
	if uc.password == nil {
		return nil, errors.New("ent: missing required field \"password\"")
	}
	return uc.sqlSave(ctx)
}

// SaveX calls Save and panics if Save returns an error.
func (uc *UserCreate) SaveX(ctx context.Context) *User {
	v, err := uc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

func (uc *UserCreate) sqlSave(ctx context.Context) (*User, error) {
	var (
		u    = &User{config: uc.config}
		spec = &sqlgraph.CreateSpec{
			Table: user.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: user.FieldID,
			},
		}
	)
	if value := uc.username; value != nil {
		spec.Fields = append(spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  *value,
			Column: user.FieldUsername,
		})
		u.Username = *value
	}
	if value := uc.password; value != nil {
		spec.Fields = append(spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  *value,
			Column: user.FieldPassword,
		})
		u.Password = *value
	}
	if err := sqlgraph.CreateNode(ctx, uc.driver, spec); err != nil {
		if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return nil, err
	}
	id := spec.ID.Value.(int64)
	u.ID = int(id)
	return u, nil
}
