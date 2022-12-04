package main

import (
	"context"
	"net/http"

	"github.com/koalatea/authserver/server/ent"
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
	router := http.NewServeMux()
	oidc.RegisterHandlers(router)

	if err := http.ListenAndServe("0.0.0.0:8080", router); err != nil {
		return err
	}
	return nil
}
