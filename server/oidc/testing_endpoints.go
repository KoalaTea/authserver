package oidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	goauth "golang.org/x/oauth2"
)

func RegisterTestHandlers(router *http.ServeMux) {
	router.Handle("/", otelhttp.NewHandler(http.HandlerFunc(HomeHandler(clientConf)), "/"))
	router.Handle("/callback", otelhttp.NewHandler(http.HandlerFunc(CallbackHandler(clientConf)), "/callback"))
}

// newBasicClient returns a client which always sends along basic auth
// credentials.
func newBasicClient(clientID string, clientSecret string) *basicClient {
	return &basicClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		client: http.Client{
			Timeout: time.Second * 5,
		},
	}
}

type basicClient struct {
	clientID     string
	clientSecret string

	client http.Client
}

// Post sends a request to the given uri with a payload of url values.
func (c *basicClient) Post(uri string, payload url.Values) (res *http.Response, body string, err error) {
	req, err := http.NewRequest(http.MethodPost, uri, bytes.NewReader([]byte(payload.Encode())))
	if err != nil {
		return
	}

	req.SetBasicAuth(c.clientID, c.clientSecret)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = c.client.Do(req)
	if err != nil {
		return
	}

	bodyBytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}
	// reset body for re-reading
	res.Body = ioutil.NopCloser(bytes.NewReader(bodyBytes))

	return res, string(bodyBytes), err
}

// resetPKCE cleans up PKCE details and returns the code verifier.
func resetPKCE(w http.ResponseWriter) (codeVerifier string) {
	// remove cookie that informs the client the callback request was a PKCE
	// request.
	http.SetCookie(w, &http.Cookie{
		Name:    cookiePKCE,
		Path:    "/",
		Expires: time.Unix(0, 0),
	})

	codeVerifier = pkceCodeVerifier
	pkceCodeVerifier = ""

	return codeVerifier
}

// isPKCE detects whether a PKCE auth request was made.
func isPKCE(r *http.Request) bool {
	cookie, err := r.Cookie(cookiePKCE)
	if err != nil {
		return false
	}

	return cookie.Value == "true"
}

func CallbackHandler(c goauth.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		codeVerifier := resetPKCE(rw)
		rw.Write([]byte(`<h1>Callback site</h1><a href="/">Go back</a>`))
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		if req.URL.Query().Get("error") != "" {
			rw.Write([]byte(fmt.Sprintf(`<h1>Error!</h1>
			Error: %s<br>
			Error Hint: %s<br>
			Description: %s<br>
			<br>`,
				req.URL.Query().Get("error"),
				req.URL.Query().Get("error_hint"),
				req.URL.Query().Get("error_description"),
			)))
			return
		}

		client := newBasicClient(c.ClientID, c.ClientSecret)
		if req.URL.Query().Get("revoke") != "" {
			revokeURL := strings.Replace(c.Endpoint.TokenURL, "token", "revoke", 1)
			payload := url.Values{
				"token_type_hint": {"refresh_token"},
				"token":           {req.URL.Query().Get("revoke")},
			}
			resp, body, err := client.Post(revokeURL, payload)
			if err != nil {
				rw.Write([]byte(fmt.Sprintf(`<p>Could not revoke token %s</p>`, err)))
				return
			}

			rw.Write([]byte(fmt.Sprintf(`<p>Received status code from the revoke endpoint:<br><code>%d</code></p>`, resp.StatusCode)))
			if body != "" {
				rw.Write([]byte(fmt.Sprintf(`<p>Got a response from the revoke endpoint:<br><code>%s</code></p>`, body)))
			}

			rw.Write([]byte(fmt.Sprintf(`<p>These tokens have been revoked, try to use the refresh token by <br><a href="%s">by clicking here</a></p>`, "?refresh="+url.QueryEscape(req.URL.Query().Get("revoke")))))
			rw.Write([]byte(fmt.Sprintf(`<p>Try to use the access token by <br><a href="%s">by clicking here</a></p>`, "/protected?token="+url.QueryEscape(req.URL.Query().Get("access_token")))))

			return
		}

		if req.URL.Query().Get("refresh") != "" {
			payload := url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {req.URL.Query().Get("refresh")},
				"scope":         {"fosite"},
			}
			_, body, err := client.Post(c.Endpoint.TokenURL, payload)
			if err != nil {
				rw.Write([]byte(fmt.Sprintf(`<p>Could not refresh token %s</p>`, err)))
				return
			}
			rw.Write([]byte(fmt.Sprintf(`<p>Got a response from the refresh grant:<br><code>%s</code></p>`, body)))
			return
		}

		if req.URL.Query().Get("code") == "" {
			rw.Write([]byte(fmt.Sprintln(`<p>Could not find the authorize code. If you've used the implicit grant, check the
			browser location bar for the
			access token <small><a href="http://en.wikipedia.org/wiki/Fragment_identifier#Basics">(the server side does not have access to url fragments)</a></small>
			</p>`,
			)))
			return
		}

		rw.Write([]byte(fmt.Sprintf(`<p>Amazing! You just got an authorize code!:<br><code>%s</code></p>
		<p>Click <a href="/">here to return</a> to the front page</p>`,
			req.URL.Query().Get("code"),
		)))

		// We'll check whether we sent a code+PKCE request, and if so, send the code_verifier along when requesting the access token.
		var opts []goauth.AuthCodeOption
		if isPKCE(req) {
			opts = append(opts, goauth.SetAuthURLParam("code_verifier", codeVerifier))
		}

		token, err := c.Exchange(context.Background(), req.URL.Query().Get("code"), opts...)
		if err != nil {
			rw.Write([]byte(fmt.Sprintf(`<p>I tried to exchange the authorize code for an access token but it did not work but got error: %s</p>`, err.Error())))
			return
		}

		rw.Write([]byte(fmt.Sprintf(`<p>Cool! You are now a proud token owner.<br>
		<ul>
			<li>
				Access token (click to make <a href="%s">authorized call</a>):<br>
				<code>%s</code>
			</li>
			<li>
				Refresh token (click <a href="%s">here to use it</a>) (click <a href="%s">here to revoke it</a>):<br>
				<code>%s</code>
			</li>
			<li>
				Extra info: <br>
				<code>%s</code>
			</li>
		</ul>`,
			"/protected?token="+token.AccessToken,
			token.AccessToken,
			"?refresh="+url.QueryEscape(token.RefreshToken),
			"?revoke="+url.QueryEscape(token.RefreshToken)+"&access_token="+url.QueryEscape(token.AccessToken),
			token.RefreshToken,
			token,
		)))
	}
}

// A valid oauth2 client (check the store) that additionally requests an OpenID Connect id token
var clientConf = goauth.Config{
	ClientID:     "my-client",
	ClientSecret: "foobar",
	RedirectURL:  "http://localhost:8080/callback",
	Scopes:       []string{"photos", "openid", "offline"},
	Endpoint: goauth.Endpoint{
		TokenURL: "http://localhost:8080/oidc/token",
		AuthURL:  "http://localhost:8080/oidc/auth",
	},
}

const cookiePKCE = "isPKCE"

var (
	// pkceCodeVerifier stores the generated random value which the client will on-send to the auth server with the received
	// authorization code. This way the oauth server can verify that the base64URLEncoded(sha265(codeVerifier)) matches
	// the stored code challenge, which was initially sent through with the code+PKCE authorization request to ensure
	// that this is the original user-agent who requested the access token.
	pkceCodeVerifier string

	// pkceCodeChallenge stores the base64(sha256(codeVerifier)) which is sent from the
	// client to the auth server as required for PKCE.
	pkceCodeChallenge string
)

// The following sets up the requirements for generating a standards compliant PKCE code verifier.
const codeVerifierLenMin = 43
const codeVerifierLenMax = 128
const codeVerifierAllowedLetters = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ._~"

func generateCodeVerifier(n int) string {
	// Enforce standards compliance...
	if n < codeVerifierLenMin {
		n = codeVerifierLenMin
	}
	if n > codeVerifierLenMax {
		n = codeVerifierLenMax
	}

	// Randomly choose some allowed characters...
	b := make([]byte, n)
	for i := range b {
		// ensure we use non-deterministic random ints.
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(len(codeVerifierAllowedLetters))))
		b[i] = codeVerifierAllowedLetters[j.Int64()]
	}

	return string(b)
}

func generateCodeChallenge(codeVerifier string) string {
	// Create a sha-265 hash from the code verifier...
	s256 := sha256.New()
	s256.Write([]byte(codeVerifier))

	// Then base64 encode the hash sum to create a code challenge...
	return base64.RawURLEncoding.EncodeToString(s256.Sum(nil))
}

func HomeHandler(c goauth.Config) func(rw http.ResponseWriter, req *http.Request) {
	return func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			// The "/" pattern matches everything, so we need to check that
			// we're at the root here.
			return
		}

		// rotate PKCE secrets
		pkceCodeVerifier = generateCodeVerifier(64)
		pkceCodeChallenge = generateCodeChallenge(pkceCodeVerifier)

		rw.Write([]byte(fmt.Sprintf(`
		<p>You can obtain an access token using various methods</p>
		<ul>
			<li>
				<a href="%s">Authorize code grant (with OpenID Connect)</a>
			</li>
			<li>
				<a href="%s" onclick="setPKCE()">Authorize code grant (with OpenID Connect) with PKCE</a>
			</li>
			<li>
				<a href="%s">Implicit grant (with OpenID Connect)</a>
			</li>
			<li>
				Client credentials grant <a href="/client">using primary secret</a> or <a href="/client-new">using rotateted secret</a>
			</li>
			<li>
				<a href="/owner">Resource owner password credentials grant</a>
			</li>
			<li>
				<a href="%s">Refresh grant</a>. <small>You will first see the login screen which is required to obtain a valid refresh token.</small>
			</li>
			<li>
				<a href="%s">Make an invalid request</a>
			</li>
		</ul>

		<script type="text/javascript">
			function setPKCE() {
				// push in a cookie that the user-agent can check to see if last request was a PKCE request.
				document.cookie = '`+cookiePKCE+`=true';
			}
			
			(function(){
				// clear existing isPKCE cookie if returning to the home page.
				document.cookie = '`+cookiePKCE+`=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
			})();
		</script>`,
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce&code_challenge="+pkceCodeChallenge+"&code_challenge_method=S256",
			"http://localhost:8080/oidc/auth?client_id=my-client&redirect_uri=http%3A%2F%2Flocalhost%3A3846%2Fcallback&response_type=token%20id_token&scope=fosite%20openid&state=some-random-state-foobar&nonce=some-random-nonce",
			c.AuthCodeURL("some-random-state-foobar")+"&nonce=some-random-nonce",
			"/oauth2/auth?client_id=my-client&scope=fosite&response_type=123&redirect_uri=http://localhost:3846/callback",
		)))
	}
}
