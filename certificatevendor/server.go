package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/debug"
	"github.com/koalatea/authserver/certificatevendor/certificates"
	"github.com/koalatea/authserver/certificatevendor/graphql"
)

type Server struct {
	Certificates *certificates.CertProvider
	HTTP         *http.Server
}

func newGraphqlHandler(certs *certificates.CertProvider) http.Handler {
	server := handler.NewDefaultServer(graphql.NewSchema(certs))
	server.Use(&debug.Tracer{})
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		server.ServeHTTP(w, req)
	})
}

func NewServer() (*Server, error) {
	certs, err := certificates.New()
	if err != nil {
		return nil, err
	}

	router := http.NewServeMux()
	router.Handle("/graphql", newGraphqlHandler(certs))
	httpSrv := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: router,
	}

	return &Server{
		HTTP: httpSrv,
	}, nil
}

func (srv *Server) Run(ctx context.Context) error {
	defer srv.Close()
	slog.InfoContext(ctx, "CertificateVendor HTTP started", "http_addr", srv.HTTP.Addr)
	if err := srv.HTTP.ListenAndServe(); err != nil {
		return fmt.Errorf("stopped http server: %w", err)
	}
	return nil
}

func (srv *Server) Close() error {
	return srv.HTTP.Shutdown(context.Background())
}
