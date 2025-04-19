package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"

	"entgo.io/contrib/entgql"
	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/debug"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/XSAM/otelsql"
	"github.com/koalatea/authserver/server/certificates"
	"github.com/koalatea/authserver/server/ent"
	"github.com/koalatea/authserver/server/ent/migrate"
	"github.com/koalatea/authserver/server/graphql"
	internalHttp "github.com/koalatea/authserver/server/internal/http"
	"github.com/koalatea/authserver/server/internal/www"
	"github.com/koalatea/authserver/server/oauthclient"
	"github.com/koalatea/authserver/server/oidc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Server struct {
	HTTP        *http.Server
	MetricsHTTP *http.Server
	graph       *ent.Client
}

func newServer(ctx context.Context, options ...func(*Config)) (*Server, error) {
	cfg := &Config{}
	for _, opt := range options {
		opt(cfg)
	}

	// Initialize oauth config
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
		slog.ErrorContext(ctx, "Failed to generate keys for usage in oauth flow", "err", err)
	}

	// Create Ent Client and Initialize graph schema
	graph, err := dbConnect(ctx)
	if err != nil {
		return nil, err
	}

	// Create Certificate Provider
	certProvider, err := certificates.NewCertProvider(graph)
	if err != nil {
		slog.ErrorContext(ctx, "failed to initialize certProvider", "err", err)
	}

	// Create OIDC Provider
	oidcProvider := oidc.NewOIDCProvider(graph)
	httpLogger := log.New(os.Stderr, "[HTTP] ", log.Flags())
	routes := internalHttp.RouteMap{
		"/graphql/playground": internalHttp.Endpoint{
			Handler: playground.Handler("playground", "/graphql"),
		},
		"/graphql": internalHttp.Endpoint{
			Handler: newGraphqlHandler(graph, certProvider),
		},
		"/oauth/login": internalHttp.Endpoint{
			Handler:              oauthclient.NewOAuthLoginHandler(oauth, privKey),
			AllowUnauthenticated: true,
		},
		"/oauth/authorize": internalHttp.Endpoint{
			Handler:              oauthclient.NewOAuthAuthorizationHandler(oauth, pubKey, graph, "https://www.googleapis.com/oauth2/v3/userinfo"),
			AllowUnauthenticated: true,
		},
		// trailing slash is required to work with react
		"/www/": internalHttp.Endpoint{
			Handler: www.NewHandler(httpLogger),
		},
	}
	routes.Extend(oidcProvider.GetHandlers())

	// If performance profiling has been enabled, register the profiling routes
	if cfg.PProfEnabled {
		// TODO I think recording this as a guage metric that says DEVELOPMENT ONLY FEATURE ENABLED type thing could be interesting
		// Along with guages for each one following the same preset prefix so people can alert on the metric showing up in production
		// and see which features are enabled
		// Currently these would be bypass auth and performance profiling
		slog.WarnContext(ctx, "performance profiling is enabled, do not use in production as this may leak sensitive information")
		registerProfiler(routes)
	}

	router := internalHttp.NewServer(routes, internalHttp.WithAuthenticationBypass(graph))

	// run the Metric server and the authserver
	metricsHTTP := newMetricsServer()
	s := &Server{MetricsHTTP: metricsHTTP, HTTP: &http.Server{Addr: "0.0.0.0:8080", Handler: router}}
	return s, nil
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

func dbConnect(ctx context.Context) (*ent.Client, error) {
	// in memory
	mysqlDSN := "file:ent?mode=memory&cache=shared&_fk=1"
	// file on disk
	// mysqlDSN := "file:server/nopush/db.sql?_fk=1"

	// Do not know if this actually does some tracing stuff or not. XSAM/otelsql though
	db, err := otelsql.Open(dialect.SQLite, mysqlDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	drv := entsql.OpenDB(dialect.SQLite, db)
	graph := ent.NewClient(ent.Driver(drv))

	// non XSAM/otelsql
	// graph, err := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1") // TODO real graph db setup
	// if err != nil {
	// 	return err
	// }

	// TODO real setup of DB. This might be non problem because it may fail if already initialized so log failure continue
	if err = graph.Schema.Create(
		context.Background(),
		migrate.WithGlobalUniqueID(true),
	); err != nil {
		graph.Close()
		return nil, fmt.Errorf("failed to initialize graph schema: %w", err)
	}
	return graph, nil
}

func newGraphqlHandler(graph *ent.Client, certProvider *certificates.CertProvider) http.Handler {
	server := handler.NewDefaultServer(graphql.NewSchema(graph, certProvider))
	server.Use(entgql.Transactioner{TxOpener: graph})
	server.Use(&debug.Tracer{})
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		server.ServeHTTP(w, req)
	})
}

func (srv *Server) Run(ctx context.Context) error {
	defer srv.Close()
	go func() {
		slog.InfoContext(ctx, "Metrics HTTP started", "metrics_addr", srv.MetricsHTTP.Addr)
		if err := srv.MetricsHTTP.ListenAndServe(); err != nil {
			slog.WarnContext(ctx, "stopped metrics http server", "err", err)
		}
	}()
	slog.InfoContext(ctx, "AutherServer HTTP started", "http_addr", srv.HTTP.Addr)
	if err := srv.HTTP.ListenAndServe(); err != nil {
		return fmt.Errorf("stopped http server: %w", err)
	}
	return nil
}

func (srv *Server) Close() error {
	srv.HTTP.Shutdown(context.Background())
	if srv.MetricsHTTP != nil {
		srv.MetricsHTTP.Shutdown(context.Background())
	}
	return srv.graph.Close()
}

func registerProfiler(router internalHttp.RouteMap) {
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
