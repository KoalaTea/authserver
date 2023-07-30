package main

import (
	"context"
	"fmt"
	"net/http"

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
	"github.com/koalatea/authserver/server/oidc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
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

func (srv *Server) Run(ctx context.Context) error {
	//https://github.com/ory/hydra/blob/c3af131e131e0e5f5584708a45c5c7e91d31bac9/persistence/sql/persister_oauth2.go#L210 look at this for some inspiration
	// largely wondering why seperate right now
	router := http.NewServeMux()
	// can I register a router in a nother router? can I middleware the router?

	// Do not know if this actually does some tracing stuff or not. XSAM/otelsql though
	db, err := otelsql.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
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
		fmt.Printf("failed to initialize graph schema: %w", err)
	}
	_, err = graph.User.Create().SetName("koalateahardcoded").SetOAuthID("idc").SetSessionToken("123").Save(context.Background()) // TODO real default user/setup
	if err != nil {
		fmt.Printf("Failed to create default user: %s", err)
	}
	certProvider, err := certificates.NewCertProvider()
	if err != nil {
		fmt.Printf("failed to initialize certProvider")
	}
	server := handler.NewDefaultServer(graphql.NewSchema(graph, certProvider))
	server.Use(entgql.Transactioner{TxOpener: graph})
	server.Use(&debug.Tracer{})

	router.Handle("/graphql/playground", auth.HandleUser(graph)(otelhttp.NewHandler(playground.Handler("playground", "/graphql"), "/graphql/playground")))
	router.Handle("/graphql",
		auth.HandleUser(graph)(otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			server.ServeHTTP(w, req)
		}), "/graphql")))

	oidcProvider := oidc.NewOIDCProvider(graph)
	oidcProvider.RegisterHandlers(router, auth.HandleUser(graph))

	if err := http.ListenAndServe("0.0.0.0:8080", router); err != nil {
		return err
	}
	return nil
}
