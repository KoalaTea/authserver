package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/koalatea/authserver/server/ent"
<<<<<<< HEAD
	"github.com/koalatea/authserver/server/ent/oidcauthcode"
=======
>>>>>>> ff9bb31c5c4e40c25f470da291de5dcb423512a1
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"gopkg.in/square/go-jose.v2"
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
func (o *OIDCStorage) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	accessRequest, err := o.client.AccessRequest.
		Create().
		SetRequestedScopes(requester.GetRequestedScopes()).
		SetGrantedScopes(requester.GetGrantedScopes()).
		SetRequestedAudiences(requester.GetRequestedAudience()).
		SetGrantedAudiences(requester.GetGrantedAudience()).
		SetRequest(requester.GetID()).
		SetForm(requester.GetRequestForm().Encode()).
		SetActive(true).
		Save(ctx)
	if err != nil {
		fmt.Printf("%w\n", err)
		return err
	}

	session := requester.GetSession().(*openid.DefaultSession)
	oidcSession, err := o.client.OIDCSession.
		Create().
		SetIssuer(session.Claims.Issuer).
		SetSubject(session.Claims.Subject).
		SetAudiences(session.Claims.Audience).
		SetExpiresAt(session.Claims.ExpiresAt).
		SetIssuedAt(session.Claims.IssuedAt).
		SetRequestedAt(session.Claims.RequestedAt).
		SetAuthTime(session.Claims.AuthTime).
		Save(ctx)
	if err != nil {
		fmt.Printf("%w\n", err)
		return err
	}

	_, err = o.client.OIDCAuthCode.Create().
		SetAuthorizationCode(authorizeCode).
		SetAccessRequest(accessRequest).
		SetSession(oidcSession).
		Save(ctx)
	if err != nil {
		fmt.Printf("%w\n", err)
		return err
	}
	return nil
}

// GetOpenIDConnectSession returns error
// - nil if a session was found,
// - ErrNoSessionFound if no session was found
// - or an arbitrary error if an error occurred.
func (o *OIDCStorage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	fmt.Println("\n\nDOES THIS RUN?\n\n")
	sess, err := o.client.OIDCAuthCode.Query().Where(oidcauthcode.AuthorizationCode(authorizeCode)).QuerySession().Only(ctx)
	if err != nil {
		return nil, err
	}
	session := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      sess.Issuer,
			Subject:     sess.Subject,
			Audience:    sess.Audiences,
			ExpiresAt:   sess.ExpiresAt,
			IssuedAt:    sess.IssuedAt,
			RequestedAt: sess.RequestedAt, // Extra
			AuthTime:    sess.AuthTime,    // Extra
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
	temp, _ := o.GetClient(ctx, "my-client")
	req := fosite.NewAuthorizeRequest()
	req.SetSession(session)
	req.Merge(requester)
	req.Client = temp
	_ = req.GetRequestForm().Get("code")
	return req, nil
}

// DeleteOpenIDConnectSession removes an open id connect session from the store.
func (o *OIDCStorage) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	// remove authorizecode from the db
	// stored_auth_code, err := o.client.OIDCAuthCode.Query().Where(oidcauthcode.AuthorizationCode(authorizeCode)).Only(ctx)
	// if err == nil {
	// 	return err
	// }
	// o.client.OIDCAuthCode.DeleteOne(stored_auth_code)
	// if err != nil {
	// 	return err
	// }
	fmt.Println("\n\nDOES THIS RUN2?\n\n")
	return nil
}

func (o *OIDCStorage) GetClient(_ context.Context, id string) (fosite.Client, error) {
	// I don't want to actually store clients yet so I will be using a hardcoded one
	// TODO: fix this lol
	return &fosite.DefaultClient{
		ID:             id,
		Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
		RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
		RedirectURIs:   []string{"http://localhost:8080/callback"},
		ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
		Scopes:         []string{"fosite", "openid", "photos", "offline"},
	}, nil
}

func (o *OIDCStorage) SetTokenLifespans(clientID string, lifespans *fosite.ClientLifespanConfig) error {
	fmt.Println("\n\nDOES THIS RUN3?\n\n")
	return fosite.ErrNotFound
}

func (o *OIDCStorage) ClientAssertionJWTValid(_ context.Context, jti string) error {
	fmt.Println("\n\nDOES THIS RUN4?\n\n")
	return nil
}

func (o *OIDCStorage) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	fmt.Println("\n\nDOES THIS RUN5?\n\n")
	return nil
}

func (o *OIDCStorage) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	fmt.Println("\n\nDOES THIS RUN6?\n\n")
	accessRequest, err := o.client.AccessRequest.
		Create().
		SetRequestedScopes(req.GetRequestedScopes()).
		SetGrantedScopes(req.GetGrantedScopes()).
		SetRequestedAudiences(req.GetRequestedAudience()).
		SetGrantedAudiences(req.GetGrantedAudience()).
		SetRequest(req.GetID()).
		SetForm(req.GetRequestForm().Encode()).
		SetActive(true).
		Save(ctx)
	if err != nil {
		fmt.Printf("%w\n", err)
		return err
	}

	session := req.GetSession().(*openid.DefaultSession)
	oidcSession, err := o.client.OIDCSession.
		Create().
		SetIssuer(session.Claims.Issuer).
		SetSubject(session.Claims.Subject).
		SetAudiences(session.Claims.Audience).
		SetExpiresAt(session.Claims.ExpiresAt).
		SetIssuedAt(session.Claims.IssuedAt).
		SetRequestedAt(session.Claims.RequestedAt).
		SetAuthTime(session.Claims.AuthTime).
		Save(ctx)
	if err != nil {
		fmt.Printf("%w\n", err)
		return err
	}

	_, err = o.client.OIDCAuthCode.Create().
		SetAuthorizationCode(code).
		SetAccessRequest(accessRequest).
		SetSession(oidcSession).
		Save(ctx)
	if err != nil {
		fmt.Printf("%w\n", err)
		return err
	}
	return nil
}

func (o *OIDCStorage) GetAuthorizeCodeSession(ctx context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	// url.ParseQuery(r.Form)
	// fmt.Printf("\n\nAUTHCODE %s\n\n", code)
	// fmt.Println("\n\nDOES THIS RUN7?\n\n") // yes
	sess, err := o.client.OIDCAuthCode.Query().Where(oidcauthcode.AuthorizationCode(code)).QuerySession().Only(ctx)
	if err != nil {
		fmt.Printf("%w", err)
		return nil, err
	}
	session := &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      sess.Issuer,
			Subject:     sess.Subject,
			Audience:    sess.Audiences,
			ExpiresAt:   sess.ExpiresAt,
			IssuedAt:    sess.IssuedAt,
			RequestedAt: sess.RequestedAt, // Extra
			AuthTime:    sess.AuthTime,    // Extra
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
	req := fosite.NewAuthorizeRequest()
	temp, _ := o.GetClient(ctx, "my-client")
	req.Client = temp
	req.SetSession(session)
	req.GrantScope("openid")
	return req, nil
}

func (o *OIDCStorage) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	fmt.Println("\n\nDOES THIS RUN8?\n\n")
	return nil
}

func (o *OIDCStorage) CreatePKCERequestSession(_ context.Context, code string, req fosite.Requester) error {
	fmt.Println("\n\nDOES THIS RUN9?\n\n") // yes but why
	return nil
}

func (o *OIDCStorage) GetPKCERequestSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	fmt.Println("\n\nDOES THIS RUN10?\n\n")
	req := fosite.NewAuthorizeRequest()
	temp, _ := o.GetClient(context.Background(), "my-client")
	req.Client = temp
	req.GrantScope("openid")
	req.SetSession(&openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      "https://fosite.my-application.com",
			Subject:     "peter",
			Audience:    []string{"https://my-client.my-application.com"},
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(), // Extra
			AuthTime:    time.Now(), // Extra
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	})
	return req, nil
}

func (o *OIDCStorage) DeletePKCERequestSession(_ context.Context, code string) error {
	fmt.Println("\n\nDOES THIS RUN11?\n\n")
	return nil
}

func (o *OIDCStorage) CreateAccessTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	fmt.Println("\n\nDOES THIS RUN12?\n\n")
	return nil
}

func (o *OIDCStorage) GetAccessTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	fmt.Println("\n\nDOES THIS RUN13?\n\n")
	return nil, nil
}

func (o *OIDCStorage) DeleteAccessTokenSession(_ context.Context, signature string) error {
	fmt.Println("\n\nDOES THIS RUN14?\n\n")
	return nil
}

func (o *OIDCStorage) CreateRefreshTokenSession(_ context.Context, signature string, req fosite.Requester) error {
	fmt.Println("\n\nDOES THIS RUN15?\n\n")
	return nil
}

func (o *OIDCStorage) GetRefreshTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	fmt.Println("\n\nDOES THIS RUN16?\n\n")
	return nil, nil
}

func (o *OIDCStorage) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	fmt.Println("\n\nDOES THIS RUN17?\n\n")
	return nil
}

func (o *OIDCStorage) Authenticate(_ context.Context, name string, secret string) error {
	fmt.Println("\n\nDOES THIS RUN18?\n\n")
	return nil
}

func (o *OIDCStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	fmt.Println("\n\nDOES THIS RUN19?\n\n")
	return nil
}

func (o *OIDCStorage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	// no configuration option is available; grace period is not available with memory store
	fmt.Println("\n\nDOES THIS RUN20?\n\n")
	return nil
}

func (o *OIDCStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	fmt.Println("\n\nDOES THIS RUN21?\n\n")
	return nil
}

func (o *OIDCStorage) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	fmt.Println("\n\nDOES THIS RUN22?\n\n")
	return nil, nil
}
func (o *OIDCStorage) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	fmt.Println("\n\nDOES THIS RUN23?\n\n")
	return nil, nil
}

func (o *OIDCStorage) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	fmt.Println("\n\nDOES THIS RUN24?\n\n")
	return nil, nil
}

func (o *OIDCStorage) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	fmt.Println("\n\nDOES THIS RUN25?\n\n")
	return false, nil
}

func (o *OIDCStorage) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	fmt.Println("\n\nDOES THIS RUN26?\n\n")
	return nil
}

// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
func (o *OIDCStorage) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	fmt.Println("\n\nDOES THIS RUN27?\n\n")
	return nil
}

// GetPARSession gets the push authorization request context. If the request is nil, a new request object
// is created. Otherwise, the same object is updated.
func (o *OIDCStorage) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	fmt.Println("\n\nDOES THIS RUN28?\n\n")
	return nil, nil
}

// DeletePARSession deletes the context.
func (o *OIDCStorage) DeletePARSession(ctx context.Context, requestURI string) (err error) {
	fmt.Println("\n\nDOES THIS RUN29?\n\n")
	return nil
}
