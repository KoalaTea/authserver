package main

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/debug"
	"github.com/koalatea/authserver/certificatevendor/graphql"
	"github.com/koalatea/authserver/certificatevendor/serial"
	"github.com/koalatea/authserver/zymkey"
)

type Server struct {
	serial *serial.Serial
	signer crypto.Signer
	HTTP   *http.Server
}

func newGraphqlHandler(serialNum *serial.Serial, signer crypto.Signer) http.Handler {
	server := handler.NewDefaultServer(graphql.NewSchema(serialNum, signer))
	server.Use(&debug.Tracer{})
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		server.ServeHTTP(w, req)
	})
}

func NewServer() (*Server, error) {
	signer, err := zymkey.NewSigner(0)
	if err != nil {
		return nil, err
	}

	serialNum, err := serial.New()
	if err != nil {
		return nil, err
	}

	router := http.NewServeMux()
	router.Handle("/graphql", newGraphqlHandler(serialNum, signer))
	httpSrv := &http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: router,
	}

	return &Server{
		serial: serialNum,
		signer: signer,
		HTTP:   httpSrv,
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
