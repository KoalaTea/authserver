package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/koalatea/authserver/server/ent"
	"github.com/koalatea/authserver/server/ent/migrate"
	"github.com/koalatea/authserver/server/oidc"
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
	_, span := tracer.Start(ctx, "Run")
	router := http.NewServeMux()

	graph, err := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	if err != nil {
		return err
	}
	if err = graph.Schema.Create(
		context.Background(),
		migrate.WithGlobalUniqueID(true),
	); err != nil {
		fmt.Printf("failed to initialize graph schema: %w", err)
	}

	oidcProvider := oidc.NewOIDCProvider(graph)
	oidcProvider.RegisterHandlers(router)

	if err := http.ListenAndServe("0.0.0.0:8080", router); err != nil {
		span.End()
		return err
	}
	span.End()
	return nil
}
