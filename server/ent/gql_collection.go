// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"entgo.io/ent/dialect/sql"
	"github.com/99designs/gqlgen/graphql"
)

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (ar *AccessRequestQuery) CollectFields(ctx context.Context, satisfies ...string) (*AccessRequestQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return ar, nil
	}
	if err := ar.collectField(ctx, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return ar, nil
}

func (ar *AccessRequestQuery) collectField(ctx context.Context, op *graphql.OperationContext, field graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	return nil
}

type accessrequestPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []AccessRequestPaginateOption
}

func newAccessRequestPaginateArgs(rv map[string]interface{}) *accessrequestPaginateArgs {
	args := &accessrequestPaginateArgs{}
	if rv == nil {
		return args
	}
	if v := rv[firstField]; v != nil {
		args.first = v.(*int)
	}
	if v := rv[lastField]; v != nil {
		args.last = v.(*int)
	}
	if v := rv[afterField]; v != nil {
		args.after = v.(*Cursor)
	}
	if v := rv[beforeField]; v != nil {
		args.before = v.(*Cursor)
	}
	if v, ok := rv[whereField].(*AccessRequestWhereInput); ok {
		args.opts = append(args.opts, WithAccessRequestFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (c *CertQuery) CollectFields(ctx context.Context, satisfies ...string) (*CertQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return c, nil
	}
	if err := c.collectField(ctx, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CertQuery) collectField(ctx context.Context, op *graphql.OperationContext, field graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	return nil
}

type certPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []CertPaginateOption
}

func newCertPaginateArgs(rv map[string]interface{}) *certPaginateArgs {
	args := &certPaginateArgs{}
	if rv == nil {
		return args
	}
	if v := rv[firstField]; v != nil {
		args.first = v.(*int)
	}
	if v := rv[lastField]; v != nil {
		args.last = v.(*int)
	}
	if v := rv[afterField]; v != nil {
		args.after = v.(*Cursor)
	}
	if v := rv[beforeField]; v != nil {
		args.before = v.(*Cursor)
	}
	if v, ok := rv[whereField].(*CertWhereInput); ok {
		args.opts = append(args.opts, WithCertFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (oac *OIDCAuthCodeQuery) CollectFields(ctx context.Context, satisfies ...string) (*OIDCAuthCodeQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return oac, nil
	}
	if err := oac.collectField(ctx, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return oac, nil
}

func (oac *OIDCAuthCodeQuery) collectField(ctx context.Context, op *graphql.OperationContext, field graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	for _, field := range graphql.CollectFields(op, field.Selections, satisfies) {
		switch field.Name {
		case "accessRequest":
			var (
				alias = field.Alias
				path  = append(path, alias)
				query = &AccessRequestQuery{config: oac.config}
			)
			if err := query.collectField(ctx, op, field, path, satisfies...); err != nil {
				return err
			}
			oac.withAccessRequest = query
		case "session":
			var (
				alias = field.Alias
				path  = append(path, alias)
				query = &OIDCSessionQuery{config: oac.config}
			)
			if err := query.collectField(ctx, op, field, path, satisfies...); err != nil {
				return err
			}
			oac.withSession = query
		}
	}
	return nil
}

type oidcauthcodePaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OIDCAuthCodePaginateOption
}

func newOIDCAuthCodePaginateArgs(rv map[string]interface{}) *oidcauthcodePaginateArgs {
	args := &oidcauthcodePaginateArgs{}
	if rv == nil {
		return args
	}
	if v := rv[firstField]; v != nil {
		args.first = v.(*int)
	}
	if v := rv[lastField]; v != nil {
		args.last = v.(*int)
	}
	if v := rv[afterField]; v != nil {
		args.after = v.(*Cursor)
	}
	if v := rv[beforeField]; v != nil {
		args.before = v.(*Cursor)
	}
	if v, ok := rv[whereField].(*OIDCAuthCodeWhereInput); ok {
		args.opts = append(args.opts, WithOIDCAuthCodeFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (oc *OIDCClientQuery) CollectFields(ctx context.Context, satisfies ...string) (*OIDCClientQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return oc, nil
	}
	if err := oc.collectField(ctx, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return oc, nil
}

func (oc *OIDCClientQuery) collectField(ctx context.Context, op *graphql.OperationContext, field graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	return nil
}

type oidcclientPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OIDCClientPaginateOption
}

func newOIDCClientPaginateArgs(rv map[string]interface{}) *oidcclientPaginateArgs {
	args := &oidcclientPaginateArgs{}
	if rv == nil {
		return args
	}
	if v := rv[firstField]; v != nil {
		args.first = v.(*int)
	}
	if v := rv[lastField]; v != nil {
		args.last = v.(*int)
	}
	if v := rv[afterField]; v != nil {
		args.after = v.(*Cursor)
	}
	if v := rv[beforeField]; v != nil {
		args.before = v.(*Cursor)
	}
	if v, ok := rv[whereField].(*OIDCClientWhereInput); ok {
		args.opts = append(args.opts, WithOIDCClientFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (os *OIDCSessionQuery) CollectFields(ctx context.Context, satisfies ...string) (*OIDCSessionQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return os, nil
	}
	if err := os.collectField(ctx, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return os, nil
}

func (os *OIDCSessionQuery) collectField(ctx context.Context, op *graphql.OperationContext, field graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	return nil
}

type oidcsessionPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OIDCSessionPaginateOption
}

func newOIDCSessionPaginateArgs(rv map[string]interface{}) *oidcsessionPaginateArgs {
	args := &oidcsessionPaginateArgs{}
	if rv == nil {
		return args
	}
	if v := rv[firstField]; v != nil {
		args.first = v.(*int)
	}
	if v := rv[lastField]; v != nil {
		args.last = v.(*int)
	}
	if v := rv[afterField]; v != nil {
		args.after = v.(*Cursor)
	}
	if v := rv[beforeField]; v != nil {
		args.before = v.(*Cursor)
	}
	if v, ok := rv[whereField].(*OIDCSessionWhereInput); ok {
		args.opts = append(args.opts, WithOIDCSessionFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (u *UserQuery) CollectFields(ctx context.Context, satisfies ...string) (*UserQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return u, nil
	}
	if err := u.collectField(ctx, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *UserQuery) collectField(ctx context.Context, op *graphql.OperationContext, field graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	return nil
}

type userPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []UserPaginateOption
}

func newUserPaginateArgs(rv map[string]interface{}) *userPaginateArgs {
	args := &userPaginateArgs{}
	if rv == nil {
		return args
	}
	if v := rv[firstField]; v != nil {
		args.first = v.(*int)
	}
	if v := rv[lastField]; v != nil {
		args.last = v.(*int)
	}
	if v := rv[afterField]; v != nil {
		args.after = v.(*Cursor)
	}
	if v := rv[beforeField]; v != nil {
		args.before = v.(*Cursor)
	}
	if v, ok := rv[whereField].(*UserWhereInput); ok {
		args.opts = append(args.opts, WithUserFilter(v.Filter))
	}
	return args
}

const (
	afterField     = "after"
	firstField     = "first"
	beforeField    = "before"
	lastField      = "last"
	orderByField   = "orderBy"
	directionField = "direction"
	fieldField     = "field"
	whereField     = "where"
)

func fieldArgs(ctx context.Context, whereInput interface{}, path ...string) map[string]interface{} {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return nil
	}
	oc := graphql.GetOperationContext(ctx)
	for _, name := range path {
		var field *graphql.CollectedField
		for _, f := range graphql.CollectFields(oc, fc.Field.Selections, nil) {
			if f.Alias == name {
				field = &f
				break
			}
		}
		if field == nil {
			return nil
		}
		cf, err := fc.Child(ctx, *field)
		if err != nil {
			args := field.ArgumentMap(oc.Variables)
			return unmarshalArgs(ctx, whereInput, args)
		}
		fc = cf
	}
	return fc.Args
}

// unmarshalArgs allows extracting the field arguments from their raw representation.
func unmarshalArgs(ctx context.Context, whereInput interface{}, args map[string]interface{}) map[string]interface{} {
	for _, k := range []string{firstField, lastField} {
		v, ok := args[k]
		if !ok {
			continue
		}
		i, err := graphql.UnmarshalInt(v)
		if err == nil {
			args[k] = &i
		}
	}
	for _, k := range []string{beforeField, afterField} {
		v, ok := args[k]
		if !ok {
			continue
		}
		c := &Cursor{}
		if c.UnmarshalGQL(v) == nil {
			args[k] = c
		}
	}
	if v, ok := args[whereField]; ok && whereInput != nil {
		if err := graphql.UnmarshalInputFromContext(ctx, v, whereInput); err == nil {
			args[whereField] = whereInput
		}
	}

	return args
}

func limitRows(partitionBy string, limit int, orderBy ...sql.Querier) func(s *sql.Selector) {
	return func(s *sql.Selector) {
		d := sql.Dialect(s.Dialect())
		s.SetDistinct(false)
		with := d.With("src_query").
			As(s.Clone()).
			With("limited_query").
			As(
				d.Select("*").
					AppendSelectExprAs(
						sql.RowNumber().PartitionBy(partitionBy).OrderExpr(orderBy...),
						"row_number",
					).
					From(d.Table("src_query")),
			)
		t := d.Table("limited_query").As(s.TableName())
		*s = *d.Select(s.UnqualifiedColumns()...).
			From(t).
			Where(sql.LTE(t.C("row_number"), limit)).
			Prefix(with)
	}
}