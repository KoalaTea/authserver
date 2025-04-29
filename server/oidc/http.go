package oidc

import (
	"net/http"

	authserverhttp "github.com/koalatea/authserver/server/internal/http"
)

func (o *OIDCProvider) Routes() authserverhttp.RouteMap {
	// TODO Set up oauth2 endpoints
	routes := authserverhttp.RouteMap{
		"/oidc/auth": authserverhttp.Endpoint{
			Handler: http.HandlerFunc(o.authEndpoint),
		},
		"/oidc/token": authserverhttp.Endpoint{
			Handler: http.HandlerFunc(o.tokenEndpoint),
		},
		"/oidc/revoke": authserverhttp.Endpoint{
			Handler: http.HandlerFunc(o.revokeEndpoint),
		},
		"/oidc/introspect": authserverhttp.Endpoint{
			Handler: http.HandlerFunc(o.introspectionEndpoint),
		},
	}
	return routes
}

func (o *OIDCProvider) TestRoutes() authserverhttp.RouteMap {
	routes := authserverhttp.RouteMap{
		"/": authserverhttp.Endpoint{
			AllowUnauthenticated: true,
			Handler:              http.HandlerFunc(o.HomeHandler(clientConf)),
		},
		"/callback": authserverhttp.Endpoint{
			AllowUnauthenticated: true,
			Handler:              http.HandlerFunc(o.CallbackHandler(clientConf)),
		},
	}
	return routes
}
