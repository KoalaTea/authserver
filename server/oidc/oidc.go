package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"

	"github.com/koalatea/authserver/server/ent"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

var tracer = otel.Tracer("authserver/oidc")

type OIDCProvider struct {
	oidcStorage *OIDCStorage
	oauth2      fosite.OAuth2Provider
}

func (o *OIDCProvider) RegisterHandlers(router *http.ServeMux, chain func(http.Handler) http.Handler) {
	// Set up oauth2 endpoints. You could also use gorilla/mux or any other router.
	router.Handle("/oidc/auth", otelhttp.NewHandler(chain(http.HandlerFunc(o.authEndpoint)), "/oidc/auth"))
	router.Handle("/oidc/token", otelhttp.NewHandler(chain(http.HandlerFunc(o.tokenEndpoint)), "/oidc/token"))

	// revoke tokens
	router.Handle("/oidc/revoke", otelhttp.NewHandler(chain(http.HandlerFunc(o.revokeEndpoint)), "/oidc/revoke"))
	router.Handle("/oidc/introspect", otelhttp.NewHandler(chain(http.HandlerFunc(o.introspectionEndpoint)), "/oidc/introspect"))

	// Helper functions for manual testing that things work
	o.RegisterTestHandlers(router)
}

func NewOIDCProvider(client *ent.Client) *OIDCProvider {
	secret := []byte("some-cool-secret-that-is-32bytes")
	config := &fosite.Config{
		AccessTokenLifespan: time.Minute * 30,
		GlobalSecret:        secret,
		// ...
	}
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	store := &OIDCStorage{
		client: client,
	}
	// its potential to extremely limit what is in this by picking explicit factories looking at
	// https://github.com/ory/fosite/blob/7efa846d221578f8716c7610632501631db8d27e/compose/compose.go#L62
	// but thats another days problem
	// var oauth2 = compose.Compose(config, store, privateKey)
	oauth2Provider := compose.ComposeAllEnabled(config, store, privateKey)
	oidc := &OIDCProvider{
		oidcStorage: store,
		oauth2:      oauth2Provider,
	}
	return oidc
}

// newSession is a helper function for creating a new session.
// Usually, you could do:
//
//	session = new(fosite.DefaultSession)
func newSession(user string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      "https://fosite.my-application.com",
			Subject:     user,
			Audience:    []string{"https://my-client.my-application.com"},
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(), // Extra
			AuthTime:    time.Now(), // Extra
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}
