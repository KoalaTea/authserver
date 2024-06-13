package http

import (
	"net/http"

	"github.com/koalatea/authserver/server/auth"
	"github.com/koalatea/authserver/server/ent"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// TODO might move this to internal/http make handleFunc just pattern to handler so it is a very basic gathering of routes as they 'should'
// exist in another project. Though they have some prerequisites like auth still...
type RouteMapOptions func(*RouteMap)
type RouteMap map[string]*Endpoint

// HandleFunc registers the handler function for the given pattern.
func (routes RouteMap) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request), options ...func(*Endpoint)) {
	e := &Endpoint{Handler: http.HandlerFunc(handler)}
	for _, opt := range options {
		opt(e)
	}
	routes[pattern] = e
}

// Handle registers the handler for the given pattern.
// If a handler already exists for pattern, Handle panics.
func (routes RouteMap) Handle(pattern string, handler http.Handler, options ...func(*Endpoint)) {
	e := &Endpoint{Handler: handler}
	for _, opt := range options {
		opt(e)
	}
	routes[pattern] = e
}

func (routes RouteMap) Extend(rm RouteMap, options ...RouteMapOptions) {
	for pattern, handler := range rm {
		routes.Handle(pattern, handler)
	}
}

type Endpoint struct {
	http.Handler
	AllowUnauthenticated bool
}

func AllowUnauthenticated() func(*Endpoint) {
	return func(e *Endpoint) {
		e.AllowUnauthenticated = true
	}
}

func NewRouter(graph *ent.Client, routes RouteMap, bypassAuth bool) *http.ServeMux {
	router := http.NewServeMux()
	for pattern, handler := range routes {
		registerRoute(graph, router, bypassAuth, pattern, handler)
	}
	return router
}

func registerRoute(graph *ent.Client, router *http.ServeMux, bypassAuth bool, pattern string, handler http.Handler) {
	router.Handle(pattern, applyMiddleware(graph, bypassAuth, handler, pattern))
}

func applyAuth(graph *ent.Client, chain http.Handler, bypassAuth bool) http.Handler {
	if bypassAuth {
		chain = auth.AuthenticationBypass(graph)(chain)
	} else {
		chain = auth.HandleUser(graph)(chain)
	}
	return chain
}

func applyMiddleware(graph *ent.Client, bypassAuth bool, handler http.Handler, route string) http.Handler {
	chain := handler
	chain = applyAuth(graph, chain, bypassAuth)
	chain = instrumentHttpMetrics(route, chain)
	chain = otelhttp.NewHandler(chain, route)
	return chain
}
