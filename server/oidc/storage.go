package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/koalatea/authserver/server/ent"
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
	// authorizercode = requester

	// requester
	// &{ID:f2c52fe0-3039-4863-b6c3-d70ec25f87cd RequestedAt:2022-12-03 17:58:42.507047639 +0000 UTC Client:0xc000578180 RequestedScope:[photos openid offline] GrantedScope:[openid] Form:map[nonce:[some-random-nonce]] Session:0xc0004b2800 RequestedAudience:[] GrantedAudience:[] Lang:en}
	// client
	// &{ID:my-client Secret:[36 50 97 36 49 48 36 73 120 77 100 73 54 100 46 76 73 82 90 80 112 83 102 69 119 78 111 101 117 52 114 89 51 70 104 68 82 69 115 120 70 74 88 105 107 99 103 100 82 82 65 83 116 120 85 108 115 117 69 79] RotatedSecrets:[[36 50 121 36 49 48 36 88 53 49 103 76 120 85 81 74 46 104 71 119 49 101 112 103 72 84 69 53 117 48 98 116 54 52 120 77 48 67 79 85 55 75 57 105 65 112 46 79 70 103 56 112 50 112 85 100 46 49 122 67 32]] RedirectURIs:[http://localhost:3846/callback] GrantTypes:[implicit refresh_token authorization_code password client_credentials] ResponseTypes:[id_token code token id_token token code id_token code token code id_token token] Scopes:[fosite openid photos offline] Audience:[] Public:false}
	// session
	// &{Claims:0xc0004e0000 Headers:0xc000380688 ExpiresAt:map[authorize_code:2022-12-03 18:13:42.507164448 +0000 UTC] Username: Subject:}

	// fmt.Printf("\n\nrequester\n%+v\nclient\n%+v\nsession\n%+v\n\n", requester, requester.GetClient(), requester.GetSession())
	_, err := o.client.OIDCAuthCode.Create().SetAuthorizationCode(authorizeCode).Save(ctx)
	if err != nil {
		fmt.Printf("%w\n", err)
	}
	// %!w(sqlite3.Error={1 1 0 near "RETURNING": syntax error})
	// r.GetRequestForm().Encode()
	return nil
}

// GetOpenIDConnectSession returns error
// - nil if a session was found,
// - ErrNoSessionFound if no session was found
// - or an arbitrary error if an error occurred.
func (o *OIDCStorage) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	// return user from authorizeCode
	// _, err := o.client.OIDCAuthCode.Query().Where(oidcauthcode.AuthorizationCode(authorizeCode)).Only(ctx)
	// if err == nil {
	// 	return nil, err
	// }
	fmt.Println("\n\nDOES THIS RUN?\n\n")
	temp, _ := o.GetClient(ctx, "my-client")
	req := fosite.NewAccessRequest(&openid.DefaultSession{})
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

func (o *OIDCStorage) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	fmt.Println("\n\nDOES THIS RUN6?\n\n") // yes 6 9 on the initla call 7 7 after
	// return &OAuth2RequestSQL{
	// 	Request:           r.GetID(),
	// 	ConsentChallenge:  challenge,
	// 	ID:                p.hashSignature(ctx, rawSignature, table),
	// 	RequestedAt:       r.GetRequestedAt(),
	// 	Client:            r.GetClient().GetID(),
	// 	Scopes:            strings.Join(r.GetRequestedScopes(), "|"),
	// 	GrantedScope:      strings.Join(r.GetGrantedScopes(), "|"),
	// 	GrantedAudience:   strings.Join(r.GetGrantedAudience(), "|"),
	// 	RequestedAudience: strings.Join(r.GetRequestedAudience(), "|"),
	// 	Form:              r.GetRequestForm().Encode(),
	// 	Session:           session,
	// 	Subject:           subject,
	// 	Active:            true,
	// 	Table:             table,
	// }, nil
	return nil
}

func (o *OIDCStorage) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	// url.ParseQuery(r.Form)
	fmt.Println("\n\nDOES THIS RUN7?\n\n") // yes
	req := fosite.NewAuthorizeRequest()
	req.Client = &fosite.DefaultClient{
		ID:             "my-client",
		Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
		RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
		RedirectURIs:   []string{"http://localhost:8080/callback"},
		ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
		Scopes:         []string{"fosite", "openid", "photos", "offline"},
	}
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
	req.Client = &fosite.DefaultClient{
		ID:             "my-client",
		Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
		RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
		RedirectURIs:   []string{"http://localhost:8080/callback"},
		ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
		Scopes:         []string{"fosite", "openid", "photos", "offline"},
	}
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
