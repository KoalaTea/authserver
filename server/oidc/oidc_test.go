package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/koalatea/authserver/server/ent/enttest"
	"github.com/koalatea/authserver/server/testingutils"

	_ "github.com/mattn/go-sqlite3"
	"github.com/ory/fosite"
)

type Response struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

func TestImplicitFlow(t *testing.T) {
	username := "testuser"
	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	provider := NewOIDCProvider(graph)
	user, _ := graph.User.Create().SetName(username).SetSessionToken("123").SetOAuthID("abc").Save(context.Background())
	routes := provider.GetHandlers()
	router := testingutils.NewRouter(routes, graph)
	w := httptest.NewRecorder()

	/* First step of the oidc implicit flow -> Resource Server directing user to request authentication from Identity Provider */
	// these values are hardcoded for testing
	v := url.Values{}
	v.Set("scopes", "openid") // Sets the scopes the user approved
	r, _ := http.NewRequest("POST", "/oidc/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&response_type=code&scope=openid&state=some-random-state-foobar&nonce=some-random-nonce", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	testingutils.AddUserAuthToRequest(r, user)
	// Request auth code
	router.ServeHTTP(w, r)
	/* Second step of the oidc implicit flow -> User gets redirected back to Resource server with an authentication code in the url to be used
	   by the Resource Server to get the oidc Identity token from the Identity Provider */
	// Get auth code from the redirect url there is no Resource Server so we skip redirect request
	locationString := w.Header().Get("Location")
	u, err := url.Parse(locationString)
	if err != nil {
		t.Errorf("%s", err)
	}
	m, _ := url.ParseQuery(u.RawQuery)
	code := m.Get("code")
	fmt.Printf("code: %s\n", code)

	/* Last step of the oidc implicit flow -> Resource server uses the authentication code to request a token of the user from the Identity Provider */
	// setup request for ID Token
	v = url.Values{}
	v.Set("client_id", "my-client")
	v.Set("client_secret", "foobar")
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "/oidc/token", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// request ID Token
	router.ServeHTTP(w, r)

	// Verify that we got an ID token with the test user
	response := &Response{}
	body, _ := ioutil.ReadAll(w.Body)
	json.Unmarshal(body, response)
	if response.IDToken == "" {
		t.Errorf("no IDToken received from the server\nResponse Body:\n%s", body)
	}
	// decode JWT token without verifying the signature
	token, err := jwt.ParseSigned(response.IDToken)
	if err != nil {
		t.Errorf("%+v", err)
	}
	c := &jwt.Claims{}
	// TODO verification which means correct key access
	token.UnsafeClaimsWithoutVerification(c)
	if c.Subject != username {
		t.Errorf("Incorrect subject %s", c.Subject)
	}
}

func TestClientAssertionJWTErrorsOnDupe(t *testing.T) {

	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")

	provider := NewOIDCProvider(graph)
	provider.oidcStorage.SetClientAssertionJWT(context.Background(), "aaa", time.Now().Add(time.Hour))
	err := provider.oidcStorage.SetClientAssertionJWT(context.Background(), "aaa", time.Now().Add(time.Hour*10))
	if !errors.Is(err, fosite.ErrJTIKnown) {
		t.Errorf("Duplicate JTI does not error SetClientAssertionJWT")
	}
}
