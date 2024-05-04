package oidc

import (
	"fmt"
	"log"
	"net/http"

	"github.com/koalatea/authserver/server/auth"
	"github.com/ory/fosite"
)

func (o *OIDCProvider) tokenEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// ITODO for some reason if openid is not a scope this still runs GetOpenIDConnectSession without the create getting run in the initial auth call

	// Create an empty session object which will be passed to the request handlers
	mySessionData := &fosite.DefaultSession{}

	// This will create an access request object and iterate through the registered TokenEndpointHandlers to validate the request.
	fmt.Println("Running NewAccessRequest")
	accessRequest, err := o.oauth2.NewAccessRequest(ctx, req, mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewAccessRequest: %+v", err)
		o.oauth2.WriteAccessError(ctx, rw, accessRequest, err)
		return
	}

	// TODO ... Why?
	// If this is a client_credentials grant, grant all requested scopes
	// NewAccessRequest validated that all requested scopes the client is allowed to perform
	// based on configured scope matching strategy.
	if accessRequest.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range accessRequest.GetRequestedScopes() {
			accessRequest.GrantScope(scope)
		}
	}
	fmt.Printf("%+v\n", accessRequest)

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	fmt.Println("Running NewAccessResponse")
	response, err := o.oauth2.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		log.Printf("Error occurred in NewAccessResponse: %+v", err)
		o.oauth2.WriteAccessError(ctx, rw, accessRequest, err)
		return
	}

	// All done, send the response.
	fmt.Println("Running WriteAccessResponse")
	o.oauth2.WriteAccessResponse(ctx, rw, accessRequest, response)
}

func (o *OIDCProvider) authEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	fmt.Println("Running NewAuthorizeRequest")
	ar, err := o.oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %+v", err)
		o.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return
	}
	// You have now access to authorizeRequest, Code ResponseTypes, Scopes ...

	var requestedScopes string
	for _, this := range ar.GetRequestedScopes() {
		requestedScopes += fmt.Sprintf(`<li><input type="checkbox" name="scopes" value="%s">%s</li>`, this, this)
	}

	// Normally, this would be the place where you would check if the user is logged in and gives his consent.
	// We're simplifying things and just checking if the request includes a valid username and password
	req.ParseForm()
	if req.PostForm.Get("username") != "peter" {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write([]byte(`<h1>Login page</h1>`))
		rw.Write([]byte(fmt.Sprintf(`
			<p>Howdy! This is the log in page. For this example, it is enough to supply the username.</p>
			<form method="post">
				<p>
					By logging in, you consent to grant these scopes:
					<ul>%s</ul>
				</p>
				<input type="text" name="username" /> <small>try peter</small><br>
				<input type="submit">
			</form>
		`, requestedScopes)))
		return
	}

	// let's see what scopes the user gave consent to
	for _, scope := range req.PostForm["scopes"] {
		fmt.Printf("\nscopes: %s\n", scope)
		ar.GrantScope(scope)
	}

	// Now that the user is authorized, we set up a session:
	mySessionData := newSession("peter")
	user, err := auth.UserFromContext(req.Context())
	if err == nil {
		fmt.Printf("%+v\n\n", user)
		mySessionData.Username = user.Name
	}

	// If you're using the JWT strategy, there's currently no distinction between access token and authorize code claims.
	// Therefore, you both access token and authorize code will have the same "exp" claim. If this is something you
	// need let us know on github.
	//
	// mySessionData.JWTClaims.ExpiresAt = time.Now().Add(time.Day)

	// It's also wise to check the requested scopes, e.g.:
	// if ar.GetRequestedScopes().Has("admin") {
	//     http.Error(rw, "you're not allowed to do that", http.StatusForbidden)
	//     return
	// }

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	fmt.Println("Running NewAuthorizeResponse")
	response, err := o.oauth2.NewAuthorizeResponse(ctx, ar, mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %+v", err)
		o.oauth2.WriteAuthorizeError(ctx, rw, ar, err)
		return
	}

	fmt.Println("Running WriteAuthorizeResponse")
	o.oauth2.WriteAuthorizeResponse(ctx, rw, ar, response)
}

func (o *OIDCProvider) introspectionEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	mySessionData := newSession("")
	ir, err := o.oauth2.NewIntrospectionRequest(ctx, req, mySessionData)
	if err != nil {
		log.Printf("Error occurred in NewIntrospectionRequest: %+v", err)
		o.oauth2.WriteIntrospectionError(ctx, rw, err)
		return
	}

	o.oauth2.WriteIntrospectionResponse(ctx, rw, ir)
}

func (o *OIDCProvider) revokeEndpoint(rw http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	// This will accept the token revocation request and validate various parameters.
	err := o.oauth2.NewRevocationRequest(ctx, req)

	o.oauth2.WriteRevocationResponse(ctx, rw, err)
}
