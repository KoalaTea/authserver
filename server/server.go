package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/debug"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/XSAM/otelsql"
	"github.com/koalatea/authserver/server/auth"
	"github.com/koalatea/authserver/server/certificates"
	"github.com/koalatea/authserver/server/ent"
	"github.com/koalatea/authserver/server/ent/migrate"
	"github.com/koalatea/authserver/server/graphql"
	"github.com/koalatea/authserver/server/oauthclient"
	"github.com/koalatea/authserver/server/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Server struct {
	client *ent.Client
}

func newServer(ctx context.Context, options ...func(*Server)) *Server {
	s := &Server{}
	for _, opt := range options {
		opt(s)
	}
	return s
}

func newMetricsServer() *http.Server {
	router := http.NewServeMux()
	router.Handle("/metrics", promhttp.Handler())
	return &http.Server{
		// Localhost to seperate unauthenticated metrics endpoint and keep that unauthenticated data from exposure to external
		Addr:    "127.0.0.1:9999",
		Handler: router,
	}
}

func (srv *Server) Run(ctx context.Context) error {
	//https://github.com/ory/hydra/blob/c3af131e131e0e5f5584708a45c5c7e91d31bac9/persistence/sql/persister_oauth2.go#L210 look at this for some inspiration
	// largely wondering why seperate right now
	cfg := getConfig("server/nopush/config.json")
	router := http.NewServeMux()
	// can I register a router in a nother router? can I middleware the router?

	// Do not know if this actually does some tracing stuff or not. XSAM/otelsql though
	db, err := otelsql.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	// db, err := otelsql.Open("sqlite3", "file:server/nopush/db.sql?_fk=1")

	if err != nil {
		panic(err)
	}

	drv := entsql.OpenDB(dialect.SQLite, db)
	graph := ent.NewClient(ent.Driver(drv))

	// graph, err := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1") // TODO real graph db setup
	// if err != nil {
	// 	return err
	// }
	if err = graph.Schema.Create(
		context.Background(),
		migrate.WithGlobalUniqueID(true),
	); err != nil {
		log.Printf("failed to initialize graph schema: %w", err)
	}
	certProvider, err := certificates.NewCertProvider()
	if err != nil {
		log.Printf("failed to initialize certProvider")
	}
	server := handler.NewDefaultServer(graphql.NewSchema(graph, certProvider))
	server.Use(entgql.Transactioner{TxOpener: graph})
	server.Use(&debug.Tracer{})

	registerRoute(graph, router, "/graphql/playground", playground.Handler("playground", "/graphql"))
	registerRoute(graph, router, "/graphql",
		http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			server.ServeHTTP(w, req)
		}))

	oauth := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.SecretKey,
		RedirectURL:  "http://localhost:8080/oauth/authorize",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("Failed to generate keys for usage in oauth flow: %s", err)
	}
	router.Handle("/oauth/login", oauthclient.NewOAuthLoginHandler(oauth, privKey))
	router.Handle("/oauth/authorize", oauthclient.NewOAuthAuthorizationHandler(oauth, pubKey, graph, "https://www.googleapis.com/oauth2/v3/userinfo"))

	oidcProvider := oidc.NewOIDCProvider(graph)
	registerRouteCBfunc := registerRouteCB(graph, router)
	oidcProvider.RegisterHandlers(registerRouteCBfunc)

	// IsPProfEnabled returns true if performance profiling has been enabled.
	if cfg.PProfEnabled {
		log.Printf("[WARN] Performance profiling is enabled, do not use in production as this may leak sensitive information")
		registerProfiler(router)
	}

	metricsHTTP := newMetricsServer()
	go func() {
		log.Printf("Metrics HTTP Server started on %s", metricsHTTP.Addr)
		if err := metricsHTTP.ListenAndServe(); err != nil {
			log.Printf("[WARN] stopped metrics http server: %v", err)
		}
	}()
	log.Printf("Starting HTTP server on %s", "0.0.0.0:8080")
	if err := http.ListenAndServe("0.0.0.0:8080", router); err != nil {
		return fmt.Errorf("stopped http server: %w", err)
	}
	return nil
}

func registerRouteCB(graph *ent.Client, router *http.ServeMux) func(string, http.Handler) {
	return func(pattern string, handler http.Handler) {
		router.Handle(pattern, applyMiddleware(graph, handler, pattern))
	}
}

func registerRoute(graph *ent.Client, router *http.ServeMux, pattern string, handler http.Handler) {
	router.Handle(pattern, applyMiddleware(graph, handler, pattern))
}

func applyMiddleware(graph *ent.Client, handler http.Handler, route string) http.Handler {
	chain := handler
	chain = otelhttp.NewHandler(chain, route)
	chain = instrumentHttpMetrics(route, chain)
	chain = auth.HandleUser(graph)(chain)
	return chain
}

func registerProfiler(router *http.ServeMux) {
	router.HandleFunc("/debug/pprof/", pprof.Index)
	router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	router.HandleFunc("/debug/pprof/profile", pprof.Profile)
	router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)

	// Manually add support for paths linked to by index page at /debug/pprof/
	router.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
	router.Handle("/debug/pprof/heap", pprof.Handler("heap"))
	router.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	router.Handle("/debug/pprof/block", pprof.Handler("block"))
}
