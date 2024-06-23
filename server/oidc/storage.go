package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/koalatea/authserver/server/ent"
	"github.com/koalatea/authserver/server/ent/authcode"
	"github.com/koalatea/authserver/server/ent/denylistedjti"
	"github.com/koalatea/authserver/server/ent/oauthaccesstoken"
	"github.com/koalatea/authserver/server/ent/oauthrefreshtoken"
	"github.com/koalatea/authserver/server/ent/oauthsession"
	"github.com/koalatea/authserver/server/ent/oidcauthcode"
	"github.com/koalatea/authserver/server/ent/pkce"
	"github.com/koalatea/authserver/server/ent/publicjwk"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// https://github.com/ory/fosite/tree/master/handler/openid
// https://github.com/ory/fosite/blob/master/internal/openid_id_token_storage.go
// https://github.com/ory/fosite/blob/master/storage/memory.go
// this explicit file
// https://github.com/ory/fosite/blob/master/handler/openid/storage.go
// https://github.com/ory/fosite-example/blob/99739a5bc1c676d08549207156fb365b2616e2e0/authorizationserver/oauth2.go#L16

// OIDCStorage struct to satisfy the interface for fosite
type OIDCStorage struct {
	client *ent.Client
}

// CreateOpenIDConnectSession creates an open id connect session
// for a given authorize code. This is relevant for explicit open id connect flow.
func (o *OIDCStorage) CreateOpenIDConnectSession(c context.Context, authorizeCode string, requester fosite.Requester) error {
	ctx, span := tracer.Start(c, "CreateOpenIDConnectSession")
	defer span.End()
	fmt.Printf("%s\n", authorizeCode)

	OAuthSession, err := o.toSession(ctx, requester)
	if err != nil {
		return err
	}
	_, err = o.client.OIDCAuthCode.Create().
		SetAuthorizationCode(authorizeCode).
		SetSession(OAuthSession).
		Save(ctx)
	if err != nil {
		//fmtf("%s\n", err)
		return err
	}
	return nil
}

// TODO ERROR HANDLING AND PROPER ERROR RETURNS
// TODO Clean up fmt.Prints

// GetOpenIDConnectSession returns error
// - nil if a session was found,
// - ErrNoSessionFound if no session was found
// - or an arbitrary error if an error occurred.
func (o *OIDCStorage) GetOpenIDConnectSession(c context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	ctx, span := tracer.Start(c, "GetOpenIDConnectSession")
	defer span.End()
	fmt.Printf("%s\n", authorizeCode)

	sess, err := o.client.OIDCAuthCode.Query().Where(oidcauthcode.AuthorizationCode(authorizeCode)).QuerySession().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, openid.ErrNoSessionFound
		}
		fmt.Printf("%s\n", err)
		return nil, err
	}

	temp, _ := o.GetClient(ctx, "my-client")
	req, err := toRequest(sess, temp)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (o *OIDCStorage) toSession(c context.Context, requester fosite.Requester) (*ent.OAuthSession, error) {
	session := requester.GetSession().(*openid.DefaultSession)
	ctx, span := tracer.Start(c, "toSession")
	defer span.End()
	OAuthSession, err := o.client.OAuthSession.
		Create().
		SetIssuer(session.Claims.Issuer).
		SetSubject(session.Claims.Subject).
		SetAudiences(session.Claims.Audience).
		SetExpiresAt(session.Claims.ExpiresAt).
		SetIssuedAt(session.Claims.IssuedAt).
		SetRequestedAt(session.Claims.RequestedAt).
		SetAuthTime(session.Claims.AuthTime).
		SetRequestedScopes(requester.GetRequestedScopes()).
		SetGrantedScopes(requester.GetGrantedScopes()).
		SetRequestedAudiences(requester.GetRequestedAudience()).
		SetGrantedAudiences(requester.GetGrantedAudience()).
		SetRequest(requester.GetID()).
		SetForm(requester.GetRequestForm().Encode()).
		Save(ctx)
	if err != nil {
		//fmtf("%s\n", err)
		return nil, err
	}
	return OAuthSession, err
}

func toRequest(oauthInfo *ent.OAuthSession, client fosite.Client) (fosite.Requester, error) {
	// val, err := url.ParseQuery(oauthInfo.Form)
	// if err != nil {
	// 	return nil, err
	// }
	session := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      oauthInfo.Issuer,
			Subject:     oauthInfo.Subject,
			Audience:    oauthInfo.Audiences,
			ExpiresAt:   oauthInfo.ExpiresAt,
			IssuedAt:    oauthInfo.IssuedAt,
			RequestedAt: oauthInfo.RequestedAt, // Extra
			AuthTime:    oauthInfo.AuthTime,    // Extra
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
	req := &fosite.Request{
		Client:            client,
		RequestedAt:       oauthInfo.RequestedAt,
		ID:                oauthInfo.Request,
		RequestedScope:    oauthInfo.RequestedScopes,
		RequestedAudience: oauthInfo.RequestedAudiences,
		GrantedScope:      oauthInfo.GrantedScopes,
		GrantedAudience:   oauthInfo.GrantedAudiences,
		Session:           session,
		// Form:              val, // Providing form in GetAuthorizeRequest Session breaks everything from working...
	}
	return req, nil
}

// DeleteOpenIDConnectSession removes an open id connect session from the store.
func (o *OIDCStorage) DeleteOpenIDConnectSession(c context.Context, authorizeCode string) error {
	ctx, span := tracer.Start(c, "DeleteOpenIDConnectSession")
	defer span.End()
	// remove authorizecode from the db
	stored_auth_code, err := o.client.OIDCAuthCode.Query().Where(oidcauthcode.AuthorizationCode(authorizeCode)).Only(ctx)
	if err != nil {
		return err
	}
	o.client.OIDCAuthCode.DeleteOne(stored_auth_code)
	if err != nil {
		return err
	}
	return nil
}

func (o *OIDCStorage) GetClient(c context.Context, id string) (fosite.Client, error) {
	// I don't want to actually store clients yet so I will be using a hardcoded one
	// TODO: fix this lol
	_, span := tracer.Start(c, "GetClient")
	defer span.End()
	return &fosite.DefaultClient{
		ID:     id,
		Secret: []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`), // = "foobar"
		// RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
		RedirectURIs:  []string{"http://localhost:8080/callback"},
		ResponseTypes: []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		GrantTypes:    []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
		Scopes:        []string{"fosite", "openid", "photos", "offline"},
	}, nil
}

func (o *OIDCStorage) SetTokenLifespans(clientID string, lifespans *fosite.ClientLifespanConfig) error {
	// TODO? Doesnt seem to be in hydra
	fmt.Println("SetTokenLifespans RAN")
	fmt.Printf("%#v", lifespans)
	return fosite.ErrNotFound
}

func (o *OIDCStorage) ClientAssertionJWTValid(c context.Context, jti string) error {
	ctx, span := tracer.Start(c, "ClientAssertionJWTValid")
	defer span.End()
	_, err := o.client.DenyListedJTI.
		Query().
		Where(
			denylistedjti.And(
				denylistedjti.Jti(jti),
				denylistedjti.ExpirationGTE(time.Now()),
			),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil
		}
		return err
	}
	return fosite.ErrJTIKnown
}

func (o *OIDCStorage) SetClientAssertionJWT(c context.Context, jti string, exp time.Time) error {
	ctx, span := tracer.Start(c, "SetClientAssertionJWT")
	defer span.End()
	// Delete expired JTIs
	_, err := o.client.DenyListedJTI.Delete().Where(denylistedjti.And(denylistedjti.ExpirationLTE(time.Now()))).Exec(ctx)
	if err != nil {
		return err
	}
	_, err = o.client.DenyListedJTI.Create().SetJti(jti).SetExpiration(exp).Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return fosite.ErrJTIKnown
		}
		fmt.Printf("%s\n", err)
		return err
	}
	return nil
}

func (o *OIDCStorage) CreateAuthorizeCodeSession(c context.Context, code string, req fosite.Requester) error {
	ctx, span := tracer.Start(c, "CreateAuthorizeCodeSession")
	defer span.End()

	// session := req.GetSession().(*openid.DefaultSession)
	// fmt.Printf("%#v\n", session)
	// fmt.Printf("%#v\n", session.Claims)
	// fmt.Printf("%#v\n", session.Headers)
	// AccessTokenHash:"", AuthenticationContextClassReference:"", AuthenticationMethodsReferences:[]string(nil), CodeHash:"", Extra:map[string]interface {}(nil)}
	// JTI:"", Nonce:"",
	// session.headers: &jwt.Headers{Extra:map[string]interface {}{}}
	OAuthSession, err := o.toSession(ctx, req)
	if err != nil {
		return err
	}

	_, err = o.client.AuthCode.Create().
		SetCode(code).
		SetActive(true).
		SetSession(OAuthSession).
		Save(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (o *OIDCStorage) GetAuthorizeCodeSession(c context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	ctx, span := tracer.Start(c, "GetAuthorizeCodeSession")
	defer span.End()
	fmt.Printf("%s\n", code)

	sess, err := o.client.AuthCode.Query().Where(authcode.Code(code)).QuerySession().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	temp, _ := o.GetClient(ctx, "my-client")
	req, err := toRequest(sess, temp)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (o *OIDCStorage) InvalidateAuthorizeCodeSession(c context.Context, code string) error {
	ctx, span := tracer.Start(c, "InvalidateAuthorizeCodeSession")
	defer span.End()
	stored_authcode, err := o.client.AuthCode.Query().Where(authcode.Code(code)).Only(ctx)
	if err != nil {
		return err
	}
	_, err = stored_authcode.Update().SetActive(false).Save(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (o *OIDCStorage) CreatePKCERequestSession(c context.Context, code string, req fosite.Requester) error {
	ctx, span := tracer.Start(c, "CreatePKCERequestSession")
	defer span.End()
	OAuthSession, err := o.toSession(ctx, req)
	if err != nil {
		return err
	}
	_, err = o.client.PKCE.Create().
		SetCode(code).
		SetSession(OAuthSession).
		Save(ctx)
	if err != nil {
		//fmtf("%s\n", err)
		return err
	}
	return nil
}

func (o *OIDCStorage) GetPKCERequestSession(c context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	ctx, span := tracer.Start(c, "GetPKCERequestSession")
	defer span.End()
	fmt.Printf("%s\n", code)

	sess, err := o.client.PKCE.Query().Where(pkce.Code(code)).QuerySession().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	temp, _ := o.GetClient(ctx, "my-client")
	req, err := toRequest(sess, temp)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (o *OIDCStorage) DeletePKCERequestSession(c context.Context, code string) error {
	ctx, span := tracer.Start(c, "DeletePKCERequestSession")
	defer span.End()
	stored_pkce, err := o.client.PKCE.Query().Where(pkce.Code(code)).Only(ctx)
	if err != nil {
		return err
	}
	err = o.client.PKCE.DeleteOne(stored_pkce).Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (o *OIDCStorage) CreateAccessTokenSession(c context.Context, signature string, req fosite.Requester) error {
	ctx, span := tracer.Start(c, "CreateAccessTokenSession")
	defer span.End()

	OAuthSession, err := o.toSession(ctx, req)
	if err != nil {
		return err
	}
	_, err = o.client.OAuthAccessToken.Create().
		SetSignature(signature).
		SetSession(OAuthSession).
		Save(ctx)
	if err != nil {
		//fmtf("%s\n", err)
		return err
	}
	return nil
}

func (o *OIDCStorage) GetAccessTokenSession(c context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	ctx, span := tracer.Start(c, "GetAccessTokenSession")
	defer span.End()

	sess, err := o.client.OAuthAccessToken.Query().Where(oauthaccesstoken.Signature(signature)).QuerySession().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	temp, _ := o.GetClient(ctx, "my-client")
	req, err := toRequest(sess, temp)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (o *OIDCStorage) DeleteAccessTokenSession(c context.Context, signature string) error {
	ctx, span := tracer.Start(c, "DeleteAccessTokenSession")
	defer span.End()
	// remove authorizecode from the db
	stored_access_token, err := o.client.OAuthAccessToken.Query().Where(oauthaccesstoken.Signature(signature)).Only(ctx)
	if err != nil {
		return err
	}
	err = o.client.OAuthAccessToken.DeleteOne(stored_access_token).Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (o *OIDCStorage) CreateRefreshTokenSession(c context.Context, signature string, req fosite.Requester) error {
	ctx, span := tracer.Start(c, "CreateRefreshTokenSession")
	defer span.End()

	OAuthSession, err := o.toSession(ctx, req)
	if err != nil {
		return err
	}
	_, err = o.client.OAuthRefreshToken.Create().
		SetSignature(signature).
		SetSession(OAuthSession).
		Save(ctx)
	if err != nil {
		//fmtf("%s\n", err)
		return err
	}
	return nil
}

func (o *OIDCStorage) GetRefreshTokenSession(c context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	ctx, span := tracer.Start(c, "GetRefreshTokenSession")
	defer span.End()

	sess, err := o.client.OAuthRefreshToken.Query().Where(oauthrefreshtoken.Signature(signature)).QuerySession().Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fosite.ErrNotFound
		}
		return nil, err
	}
	temp, _ := o.GetClient(ctx, "my-client")
	req, err := toRequest(sess, temp)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func (o *OIDCStorage) DeleteRefreshTokenSession(c context.Context, signature string) error {
	ctx, span := tracer.Start(c, "DeleteRefreshTokenSession")
	defer span.End()
	// remove authorizecode from the db
	stored_refresh_token, err := o.client.OAuthRefreshToken.Query().Where(oauthrefreshtoken.Signature(signature)).Only(ctx)
	if err != nil {
		return err
	}
	err = o.client.OAuthRefreshToken.DeleteOne(stored_refresh_token).Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

// TODO? Don't know that this is actually necessary seems like a sort of injection of a potentially useful function though not directly related to
// correctly doing oidc/oauth

func (o *OIDCStorage) Authenticate(c context.Context, name string, secret string) error {
	_, span := tracer.Start(c, "Authenticate")
	defer span.End()
	return nil
}

func (o *OIDCStorage) RevokeRefreshToken(c context.Context, requestID string) error {
	ctx, span := tracer.Start(c, "RevokeRefreshToken")
	defer span.End()
	// remove authorizecode from the db
	stored_refresh_token, err := o.client.OAuthRefreshToken.Query().Where(oauthrefreshtoken.HasSessionWith(oauthsession.Request(requestID))).Only(ctx)
	if err != nil {
		return err
	}
	err = o.client.OAuthRefreshToken.DeleteOne(stored_refresh_token).Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (o *OIDCStorage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	fmt.Println("RevokeRefreshTokenMaybeGracePeriod RAN")
	// no configuration option is available; grace period is not available in my curernt version of store
	// TODO?
	return o.RevokeRefreshToken(ctx, requestID)
}

func (o *OIDCStorage) RevokeAccessToken(c context.Context, requestID string) error {
	ctx, span := tracer.Start(c, "DeleteAccessTokenSession")
	defer span.End()
	// remove authorizecode from the db
	stored_access_token, err := o.client.OAuthAccessToken.Query().Where(oauthaccesstoken.HasSessionWith(oauthsession.Request(requestID))).Only(ctx)
	if err != nil {
		return err
	}
	err = o.client.OAuthAccessToken.DeleteOne(stored_access_token).Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (o *OIDCStorage) GetPublicKey(c context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	//https://github.com/ory/hydra/blob/c3af131e131e0e5f5584708a45c5c7e91d31bac9/persistence/sql/persister_jwk.go#L124
	ctx, span := tracer.Start(c, "GetPublicKey")
	defer span.End()
	key, err := o.client.PublicJWK.Query().Where(publicjwk.And(publicjwk.Issuer(issuer), publicjwk.Kid(keyId), publicjwk.Sid(subject))).Only(ctx)
	if err != nil {
		return nil, err //todo https://github.com/ory/hydra/blob/master/persistence/sql/persister_grant_jwk.go#L120 sqlcon.handleerror? what do
	}
	jwk := &jose.JSONWebKey{}
	err = json.Unmarshal([]byte(key.Key), jwk)
	if err != nil {
		return nil, err
	}

	return jwk, nil
}
func (o *OIDCStorage) GetPublicKeys(c context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	ctx, span := tracer.Start(c, "GetPublicKeys")
	defer span.End()
	keys, err := o.client.PublicJWK.Query().Where(publicjwk.And(publicjwk.Issuer(issuer), publicjwk.Sid(subject))).All(ctx)
	if err != nil {
		return nil, err //todo https://github.com/ory/hydra/blob/master/persistence/sql/persister_grant_jwk.go#L120 sqlcon.handleerror? what do
	}
	jwks := []jose.JSONWebKey{}
	for _, key := range keys {
		jwk := &jose.JSONWebKey{}
		err = json.Unmarshal([]byte(key.Key), jwk)
		if err != nil {
			return nil, err
		}
		jwks = append(jwks, *jwk)
	}
	jwkSet := &jose.JSONWebKeySet{Keys: jwks}

	return jwkSet, nil
}

func (o *OIDCStorage) GetPublicKeyScopes(c context.Context, issuer string, subject string, keyId string) ([]string, error) {
	ctx, span := tracer.Start(c, "GetPublicKeyScopes")
	defer span.End()
	key, err := o.client.PublicJWK.Query().Where(publicjwk.And(publicjwk.Issuer(issuer), publicjwk.Kid(keyId), publicjwk.Sid(subject))).Only(ctx)
	if err != nil {
		return nil, err //todo https://github.com/ory/hydra/blob/master/persistence/sql/persister_grant_jwk.go#L120 sqlcon.handleerror? what do
	}

	return key.Scopes, nil
}

func (o *OIDCStorage) IsJWTUsed(c context.Context, jti string) (bool, error) {
	ctx, span := tracer.Start(c, "IsJWTUsed")
	defer span.End()

	err := o.ClientAssertionJWTValid(ctx, jti)
	if err != nil {
		return true, nil
	}

	return false, nil
}

func (o *OIDCStorage) MarkJWTUsedForTime(c context.Context, jti string, exp time.Time) error {
	ctx, span := tracer.Start(c, "MarkJWTUsedForTime")
	defer span.End()
	return o.SetClientAssertionJWT(ctx, jti, exp)
}

// TODO? PARSESSIONTHINGS?

// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
// func (o *OIDCStorage) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
// 	fmt.Println("CreatePARSession RAN")
// 	fmt.Printf("%#v", request)
// 	return nil
// }

// // GetPARSession gets the push authorization request context. If the request is nil, a new request object
// // is created. Otherwise, the same object is updated.
// func (o *OIDCStorage) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
// 	fmt.Println("GetPARSession RAN")
// 	return nil, nil
// }

// // DeletePARSession deletes the context.
// func (o *OIDCStorage) DeletePARSession(ctx context.Context, requestURI string) (err error) {
// 	fmt.Println("DeletePARSession RAN")
// 	return nil
// }
