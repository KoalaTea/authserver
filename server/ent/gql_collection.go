// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"

	"github.com/99designs/gqlgen/graphql"
	"github.com/koalatea/authserver/server/ent/authcode"
	"github.com/koalatea/authserver/server/ent/cert"
	"github.com/koalatea/authserver/server/ent/denylistedjti"
	"github.com/koalatea/authserver/server/ent/oauthaccesstoken"
	"github.com/koalatea/authserver/server/ent/oauthclient"
	"github.com/koalatea/authserver/server/ent/oauthparrequest"
	"github.com/koalatea/authserver/server/ent/oauthrefreshtoken"
	"github.com/koalatea/authserver/server/ent/oauthsession"
	"github.com/koalatea/authserver/server/ent/oidcauthcode"
	"github.com/koalatea/authserver/server/ent/pkce"
	"github.com/koalatea/authserver/server/ent/publicjwk"
	"github.com/koalatea/authserver/server/ent/user"
)

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (ac *AuthCodeQuery) CollectFields(ctx context.Context, satisfies ...string) (*AuthCodeQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return ac, nil
	}
	if err := ac.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return ac, nil
}

func (ac *AuthCodeQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(authcode.Columns))
		selectedFields = []string{authcode.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {

		case "session":
			var (
				alias = field.Alias
				path  = append(path, alias)
				query = (&OAuthSessionClient{config: ac.config}).Query()
			)
			if err := query.collectField(ctx, oneNode, opCtx, field, path, mayAddCondition(satisfies, oauthsessionImplementors)...); err != nil {
				return err
			}
			ac.withSession = query
		case "code":
			if _, ok := fieldSeen[authcode.FieldCode]; !ok {
				selectedFields = append(selectedFields, authcode.FieldCode)
				fieldSeen[authcode.FieldCode] = struct{}{}
			}
		case "active":
			if _, ok := fieldSeen[authcode.FieldActive]; !ok {
				selectedFields = append(selectedFields, authcode.FieldActive)
				fieldSeen[authcode.FieldActive] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		ac.Select(selectedFields...)
	}
	return nil
}

type authcodePaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []AuthCodePaginateOption
}

func newAuthCodePaginateArgs(rv map[string]any) *authcodePaginateArgs {
	args := &authcodePaginateArgs{}
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
	if v, ok := rv[whereField].(*AuthCodeWhereInput); ok {
		args.opts = append(args.opts, WithAuthCodeFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (c *CertQuery) CollectFields(ctx context.Context, satisfies ...string) (*CertQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return c, nil
	}
	if err := c.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *CertQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(cert.Columns))
		selectedFields = []string{cert.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {
		case "revoked":
			if _, ok := fieldSeen[cert.FieldRevoked]; !ok {
				selectedFields = append(selectedFields, cert.FieldRevoked)
				fieldSeen[cert.FieldRevoked] = struct{}{}
			}
		case "pem":
			if _, ok := fieldSeen[cert.FieldPem]; !ok {
				selectedFields = append(selectedFields, cert.FieldPem)
				fieldSeen[cert.FieldPem] = struct{}{}
			}
		case "serialNumber":
			if _, ok := fieldSeen[cert.FieldSerialNumber]; !ok {
				selectedFields = append(selectedFields, cert.FieldSerialNumber)
				fieldSeen[cert.FieldSerialNumber] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		c.Select(selectedFields...)
	}
	return nil
}

type certPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []CertPaginateOption
}

func newCertPaginateArgs(rv map[string]any) *certPaginateArgs {
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
func (dlj *DenyListedJTIQuery) CollectFields(ctx context.Context, satisfies ...string) (*DenyListedJTIQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return dlj, nil
	}
	if err := dlj.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return dlj, nil
}

func (dlj *DenyListedJTIQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(denylistedjti.Columns))
		selectedFields = []string{denylistedjti.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {
		case "jti":
			if _, ok := fieldSeen[denylistedjti.FieldJti]; !ok {
				selectedFields = append(selectedFields, denylistedjti.FieldJti)
				fieldSeen[denylistedjti.FieldJti] = struct{}{}
			}
		case "expiration":
			if _, ok := fieldSeen[denylistedjti.FieldExpiration]; !ok {
				selectedFields = append(selectedFields, denylistedjti.FieldExpiration)
				fieldSeen[denylistedjti.FieldExpiration] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		dlj.Select(selectedFields...)
	}
	return nil
}

type denylistedjtiPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []DenyListedJTIPaginateOption
}

func newDenyListedJTIPaginateArgs(rv map[string]any) *denylistedjtiPaginateArgs {
	args := &denylistedjtiPaginateArgs{}
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
	if v, ok := rv[whereField].(*DenyListedJTIWhereInput); ok {
		args.opts = append(args.opts, WithDenyListedJTIFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (oat *OAuthAccessTokenQuery) CollectFields(ctx context.Context, satisfies ...string) (*OAuthAccessTokenQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return oat, nil
	}
	if err := oat.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return oat, nil
}

func (oat *OAuthAccessTokenQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(oauthaccesstoken.Columns))
		selectedFields = []string{oauthaccesstoken.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {

		case "session":
			var (
				alias = field.Alias
				path  = append(path, alias)
				query = (&OAuthSessionClient{config: oat.config}).Query()
			)
			if err := query.collectField(ctx, oneNode, opCtx, field, path, mayAddCondition(satisfies, oauthsessionImplementors)...); err != nil {
				return err
			}
			oat.withSession = query
		case "signature":
			if _, ok := fieldSeen[oauthaccesstoken.FieldSignature]; !ok {
				selectedFields = append(selectedFields, oauthaccesstoken.FieldSignature)
				fieldSeen[oauthaccesstoken.FieldSignature] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		oat.Select(selectedFields...)
	}
	return nil
}

type oauthaccesstokenPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OAuthAccessTokenPaginateOption
}

func newOAuthAccessTokenPaginateArgs(rv map[string]any) *oauthaccesstokenPaginateArgs {
	args := &oauthaccesstokenPaginateArgs{}
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
	if v, ok := rv[whereField].(*OAuthAccessTokenWhereInput); ok {
		args.opts = append(args.opts, WithOAuthAccessTokenFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (oc *OAuthClientQuery) CollectFields(ctx context.Context, satisfies ...string) (*OAuthClientQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return oc, nil
	}
	if err := oc.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return oc, nil
}

func (oc *OAuthClientQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(oauthclient.Columns))
		selectedFields = []string{oauthclient.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {
		case "clientID":
			if _, ok := fieldSeen[oauthclient.FieldClientID]; !ok {
				selectedFields = append(selectedFields, oauthclient.FieldClientID)
				fieldSeen[oauthclient.FieldClientID] = struct{}{}
			}
		case "secret":
			if _, ok := fieldSeen[oauthclient.FieldSecret]; !ok {
				selectedFields = append(selectedFields, oauthclient.FieldSecret)
				fieldSeen[oauthclient.FieldSecret] = struct{}{}
			}
		case "redirectUris":
			if _, ok := fieldSeen[oauthclient.FieldRedirectUris]; !ok {
				selectedFields = append(selectedFields, oauthclient.FieldRedirectUris)
				fieldSeen[oauthclient.FieldRedirectUris] = struct{}{}
			}
		case "responseTypes":
			if _, ok := fieldSeen[oauthclient.FieldResponseTypes]; !ok {
				selectedFields = append(selectedFields, oauthclient.FieldResponseTypes)
				fieldSeen[oauthclient.FieldResponseTypes] = struct{}{}
			}
		case "grantTypes":
			if _, ok := fieldSeen[oauthclient.FieldGrantTypes]; !ok {
				selectedFields = append(selectedFields, oauthclient.FieldGrantTypes)
				fieldSeen[oauthclient.FieldGrantTypes] = struct{}{}
			}
		case "scopes":
			if _, ok := fieldSeen[oauthclient.FieldScopes]; !ok {
				selectedFields = append(selectedFields, oauthclient.FieldScopes)
				fieldSeen[oauthclient.FieldScopes] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		oc.Select(selectedFields...)
	}
	return nil
}

type oauthclientPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OAuthClientPaginateOption
}

func newOAuthClientPaginateArgs(rv map[string]any) *oauthclientPaginateArgs {
	args := &oauthclientPaginateArgs{}
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
	if v, ok := rv[whereField].(*OAuthClientWhereInput); ok {
		args.opts = append(args.opts, WithOAuthClientFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (opr *OAuthPARRequestQuery) CollectFields(ctx context.Context, satisfies ...string) (*OAuthPARRequestQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return opr, nil
	}
	if err := opr.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return opr, nil
}

func (opr *OAuthPARRequestQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(oauthparrequest.Columns))
		selectedFields = []string{oauthparrequest.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {
		case "request":
			if _, ok := fieldSeen[oauthparrequest.FieldRequest]; !ok {
				selectedFields = append(selectedFields, oauthparrequest.FieldRequest)
				fieldSeen[oauthparrequest.FieldRequest] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		opr.Select(selectedFields...)
	}
	return nil
}

type oauthparrequestPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OAuthPARRequestPaginateOption
}

func newOAuthPARRequestPaginateArgs(rv map[string]any) *oauthparrequestPaginateArgs {
	args := &oauthparrequestPaginateArgs{}
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
	if v, ok := rv[whereField].(*OAuthPARRequestWhereInput); ok {
		args.opts = append(args.opts, WithOAuthPARRequestFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (ort *OAuthRefreshTokenQuery) CollectFields(ctx context.Context, satisfies ...string) (*OAuthRefreshTokenQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return ort, nil
	}
	if err := ort.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return ort, nil
}

func (ort *OAuthRefreshTokenQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(oauthrefreshtoken.Columns))
		selectedFields = []string{oauthrefreshtoken.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {

		case "session":
			var (
				alias = field.Alias
				path  = append(path, alias)
				query = (&OAuthSessionClient{config: ort.config}).Query()
			)
			if err := query.collectField(ctx, oneNode, opCtx, field, path, mayAddCondition(satisfies, oauthsessionImplementors)...); err != nil {
				return err
			}
			ort.withSession = query
		case "signature":
			if _, ok := fieldSeen[oauthrefreshtoken.FieldSignature]; !ok {
				selectedFields = append(selectedFields, oauthrefreshtoken.FieldSignature)
				fieldSeen[oauthrefreshtoken.FieldSignature] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		ort.Select(selectedFields...)
	}
	return nil
}

type oauthrefreshtokenPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OAuthRefreshTokenPaginateOption
}

func newOAuthRefreshTokenPaginateArgs(rv map[string]any) *oauthrefreshtokenPaginateArgs {
	args := &oauthrefreshtokenPaginateArgs{}
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
	if v, ok := rv[whereField].(*OAuthRefreshTokenWhereInput); ok {
		args.opts = append(args.opts, WithOAuthRefreshTokenFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (os *OAuthSessionQuery) CollectFields(ctx context.Context, satisfies ...string) (*OAuthSessionQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return os, nil
	}
	if err := os.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return os, nil
}

func (os *OAuthSessionQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(oauthsession.Columns))
		selectedFields = []string{oauthsession.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {
		case "issuer":
			if _, ok := fieldSeen[oauthsession.FieldIssuer]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldIssuer)
				fieldSeen[oauthsession.FieldIssuer] = struct{}{}
			}
		case "subject":
			if _, ok := fieldSeen[oauthsession.FieldSubject]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldSubject)
				fieldSeen[oauthsession.FieldSubject] = struct{}{}
			}
		case "audiences":
			if _, ok := fieldSeen[oauthsession.FieldAudiences]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldAudiences)
				fieldSeen[oauthsession.FieldAudiences] = struct{}{}
			}
		case "expiresAt":
			if _, ok := fieldSeen[oauthsession.FieldExpiresAt]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldExpiresAt)
				fieldSeen[oauthsession.FieldExpiresAt] = struct{}{}
			}
		case "issuedAt":
			if _, ok := fieldSeen[oauthsession.FieldIssuedAt]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldIssuedAt)
				fieldSeen[oauthsession.FieldIssuedAt] = struct{}{}
			}
		case "requestedAt":
			if _, ok := fieldSeen[oauthsession.FieldRequestedAt]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldRequestedAt)
				fieldSeen[oauthsession.FieldRequestedAt] = struct{}{}
			}
		case "authTime":
			if _, ok := fieldSeen[oauthsession.FieldAuthTime]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldAuthTime)
				fieldSeen[oauthsession.FieldAuthTime] = struct{}{}
			}
		case "requestedScopes":
			if _, ok := fieldSeen[oauthsession.FieldRequestedScopes]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldRequestedScopes)
				fieldSeen[oauthsession.FieldRequestedScopes] = struct{}{}
			}
		case "grantedScopes":
			if _, ok := fieldSeen[oauthsession.FieldGrantedScopes]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldGrantedScopes)
				fieldSeen[oauthsession.FieldGrantedScopes] = struct{}{}
			}
		case "requestedAudiences":
			if _, ok := fieldSeen[oauthsession.FieldRequestedAudiences]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldRequestedAudiences)
				fieldSeen[oauthsession.FieldRequestedAudiences] = struct{}{}
			}
		case "grantedAudiences":
			if _, ok := fieldSeen[oauthsession.FieldGrantedAudiences]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldGrantedAudiences)
				fieldSeen[oauthsession.FieldGrantedAudiences] = struct{}{}
			}
		case "request":
			if _, ok := fieldSeen[oauthsession.FieldRequest]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldRequest)
				fieldSeen[oauthsession.FieldRequest] = struct{}{}
			}
		case "form":
			if _, ok := fieldSeen[oauthsession.FieldForm]; !ok {
				selectedFields = append(selectedFields, oauthsession.FieldForm)
				fieldSeen[oauthsession.FieldForm] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		os.Select(selectedFields...)
	}
	return nil
}

type oauthsessionPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OAuthSessionPaginateOption
}

func newOAuthSessionPaginateArgs(rv map[string]any) *oauthsessionPaginateArgs {
	args := &oauthsessionPaginateArgs{}
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
	if v, ok := rv[whereField].(*OAuthSessionWhereInput); ok {
		args.opts = append(args.opts, WithOAuthSessionFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (oac *OIDCAuthCodeQuery) CollectFields(ctx context.Context, satisfies ...string) (*OIDCAuthCodeQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return oac, nil
	}
	if err := oac.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return oac, nil
}

func (oac *OIDCAuthCodeQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(oidcauthcode.Columns))
		selectedFields = []string{oidcauthcode.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {

		case "session":
			var (
				alias = field.Alias
				path  = append(path, alias)
				query = (&OAuthSessionClient{config: oac.config}).Query()
			)
			if err := query.collectField(ctx, oneNode, opCtx, field, path, mayAddCondition(satisfies, oauthsessionImplementors)...); err != nil {
				return err
			}
			oac.withSession = query
		case "authorizationCode":
			if _, ok := fieldSeen[oidcauthcode.FieldAuthorizationCode]; !ok {
				selectedFields = append(selectedFields, oidcauthcode.FieldAuthorizationCode)
				fieldSeen[oidcauthcode.FieldAuthorizationCode] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		oac.Select(selectedFields...)
	}
	return nil
}

type oidcauthcodePaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []OIDCAuthCodePaginateOption
}

func newOIDCAuthCodePaginateArgs(rv map[string]any) *oidcauthcodePaginateArgs {
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
func (pk *PKCEQuery) CollectFields(ctx context.Context, satisfies ...string) (*PKCEQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return pk, nil
	}
	if err := pk.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return pk, nil
}

func (pk *PKCEQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(pkce.Columns))
		selectedFields = []string{pkce.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {

		case "session":
			var (
				alias = field.Alias
				path  = append(path, alias)
				query = (&OAuthSessionClient{config: pk.config}).Query()
			)
			if err := query.collectField(ctx, oneNode, opCtx, field, path, mayAddCondition(satisfies, oauthsessionImplementors)...); err != nil {
				return err
			}
			pk.withSession = query
		case "code":
			if _, ok := fieldSeen[pkce.FieldCode]; !ok {
				selectedFields = append(selectedFields, pkce.FieldCode)
				fieldSeen[pkce.FieldCode] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		pk.Select(selectedFields...)
	}
	return nil
}

type pkcePaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []PKCEPaginateOption
}

func newPKCEPaginateArgs(rv map[string]any) *pkcePaginateArgs {
	args := &pkcePaginateArgs{}
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
	if v, ok := rv[whereField].(*PKCEWhereInput); ok {
		args.opts = append(args.opts, WithPKCEFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (pj *PublicJWKQuery) CollectFields(ctx context.Context, satisfies ...string) (*PublicJWKQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return pj, nil
	}
	if err := pj.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return pj, nil
}

func (pj *PublicJWKQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(publicjwk.Columns))
		selectedFields = []string{publicjwk.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {
		case "sid":
			if _, ok := fieldSeen[publicjwk.FieldSid]; !ok {
				selectedFields = append(selectedFields, publicjwk.FieldSid)
				fieldSeen[publicjwk.FieldSid] = struct{}{}
			}
		case "kid":
			if _, ok := fieldSeen[publicjwk.FieldKid]; !ok {
				selectedFields = append(selectedFields, publicjwk.FieldKid)
				fieldSeen[publicjwk.FieldKid] = struct{}{}
			}
		case "key":
			if _, ok := fieldSeen[publicjwk.FieldKey]; !ok {
				selectedFields = append(selectedFields, publicjwk.FieldKey)
				fieldSeen[publicjwk.FieldKey] = struct{}{}
			}
		case "issuer":
			if _, ok := fieldSeen[publicjwk.FieldIssuer]; !ok {
				selectedFields = append(selectedFields, publicjwk.FieldIssuer)
				fieldSeen[publicjwk.FieldIssuer] = struct{}{}
			}
		case "scopes":
			if _, ok := fieldSeen[publicjwk.FieldScopes]; !ok {
				selectedFields = append(selectedFields, publicjwk.FieldScopes)
				fieldSeen[publicjwk.FieldScopes] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		pj.Select(selectedFields...)
	}
	return nil
}

type publicjwkPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []PublicJWKPaginateOption
}

func newPublicJWKPaginateArgs(rv map[string]any) *publicjwkPaginateArgs {
	args := &publicjwkPaginateArgs{}
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
	if v, ok := rv[whereField].(*PublicJWKWhereInput); ok {
		args.opts = append(args.opts, WithPublicJWKFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (pjs *PublicJWKSetQuery) CollectFields(ctx context.Context, satisfies ...string) (*PublicJWKSetQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return pjs, nil
	}
	if err := pjs.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return pjs, nil
}

func (pjs *PublicJWKSetQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	return nil
}

type publicjwksetPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []PublicJWKSetPaginateOption
}

func newPublicJWKSetPaginateArgs(rv map[string]any) *publicjwksetPaginateArgs {
	args := &publicjwksetPaginateArgs{}
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
	if v, ok := rv[whereField].(*PublicJWKSetWhereInput); ok {
		args.opts = append(args.opts, WithPublicJWKSetFilter(v.Filter))
	}
	return args
}

// CollectFields tells the query-builder to eagerly load connected nodes by resolver context.
func (u *UserQuery) CollectFields(ctx context.Context, satisfies ...string) (*UserQuery, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil {
		return u, nil
	}
	if err := u.collectField(ctx, false, graphql.GetOperationContext(ctx), fc.Field, nil, satisfies...); err != nil {
		return nil, err
	}
	return u, nil
}

func (u *UserQuery) collectField(ctx context.Context, oneNode bool, opCtx *graphql.OperationContext, collected graphql.CollectedField, path []string, satisfies ...string) error {
	path = append([]string(nil), path...)
	var (
		unknownSeen    bool
		fieldSeen      = make(map[string]struct{}, len(user.Columns))
		selectedFields = []string{user.FieldID}
	)
	for _, field := range graphql.CollectFields(opCtx, collected.Selections, satisfies) {
		switch field.Name {
		case "name":
			if _, ok := fieldSeen[user.FieldName]; !ok {
				selectedFields = append(selectedFields, user.FieldName)
				fieldSeen[user.FieldName] = struct{}{}
			}
		case "isactivated":
			if _, ok := fieldSeen[user.FieldIsActivated]; !ok {
				selectedFields = append(selectedFields, user.FieldIsActivated)
				fieldSeen[user.FieldIsActivated] = struct{}{}
			}
		case "id":
		case "__typename":
		default:
			unknownSeen = true
		}
	}
	if !unknownSeen {
		u.Select(selectedFields...)
	}
	return nil
}

type userPaginateArgs struct {
	first, last   *int
	after, before *Cursor
	opts          []UserPaginateOption
}

func newUserPaginateArgs(rv map[string]any) *userPaginateArgs {
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

func fieldArgs(ctx context.Context, whereInput any, path ...string) map[string]any {
	field := collectedField(ctx, path...)
	if field == nil || field.Arguments == nil {
		return nil
	}
	oc := graphql.GetOperationContext(ctx)
	args := field.ArgumentMap(oc.Variables)
	return unmarshalArgs(ctx, whereInput, args)
}

// unmarshalArgs allows extracting the field arguments from their raw representation.
func unmarshalArgs(ctx context.Context, whereInput any, args map[string]any) map[string]any {
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

// mayAddCondition appends another type condition to the satisfies list
// if it does not exist in the list.
func mayAddCondition(satisfies []string, typeCond []string) []string {
Cond:
	for _, c := range typeCond {
		for _, s := range satisfies {
			if c == s {
				continue Cond
			}
		}
		satisfies = append(satisfies, c)
	}
	return satisfies
}
