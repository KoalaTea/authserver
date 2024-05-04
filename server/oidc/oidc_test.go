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

	"github.com/koalatea/authserver/server/auth"
	"github.com/koalatea/authserver/server/ent/enttest"
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

func TestGettingIDToken(t *testing.T) {

	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")

	provider := NewOIDCProvider(graph)
	router := http.NewServeMux()
	graph.User.Create().SetName("koalateahardcoded").SetSessionToken("123").SetOAuthID("abc").Save(context.Background())
	provider.RegisterHandlers(router, auth.HandleUser(graph))
	w := httptest.NewRecorder()

	// these values are hardcoded for testing
	v := url.Values{}
	v.Set("username", "peter")
	v.Set("scopes", "openid") // Sets the scopes the user approved
	r, _ := http.NewRequest("POST", "/oidc/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fcallback&response_type=code&scope=openid&state=some-random-state-foobar&nonce=some-random-nonce", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Get auth code
	router.ServeHTTP(w, r)
	locationString := w.Header().Get("Location")
	u, err := url.Parse(locationString)
	if err != nil {
		t.Errorf("%s", err)
	}
	m, _ := url.ParseQuery(u.RawQuery)
	code := m.Get("code")
	fmt.Printf("code: %s\n", code)

	// use auth code for a new token
	v = url.Values{}
	v.Set("client_id", "my-client")
	v.Set("client_secret", "foobar")
	v.Set("grant_type", "authorization_code")
	v.Set("code", code)
	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "/oidc/token", strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// r.SetBasicAuth(url.QueryEscape("my-client"), url.QueryEscape("foobar"))

	router.ServeHTTP(w, r)
	response := &Response{}
	body, _ := ioutil.ReadAll(w.Body)
	fmt.Printf("%s", body)
	json.Unmarshal(body, response)
	if response.IDToken == "" {
		t.Error("what")
	}
	// current version
	// {
	// 	"at_hash": "7jG_bBlmSapKjM1aaUkBFg",
	// 	"aud": [
	// 	  "https://my-client.my-application.com",
	// 	  "my-client"
	// 	],
	// 	"auth_time": 1677077516,
	// 	"exp": 1677099116,
	// 	"iat": 1677077516,
	// 	"iss": "https://fosite.my-application.com",
	// 	"jti": "249c4828-595f-4665-9453-4d8ab2db23b0",
	// 	"rat": 1677077516,
	// 	"sub": "peter"
	//   }
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
