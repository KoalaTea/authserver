package main

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/debug"
	"github.com/koalatea/authserver/certificatevendor/certificates"
	"github.com/koalatea/authserver/certificatevendor/graphql"
)

func CAHandler(certs *certificates.CertProvider) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		caCert := certs.CA()
		if caCert == nil {
			http.Error(w, "CA certificate not found", http.StatusNotFound)
			return
		}
		// PEM Encode
		caPEM := new(bytes.Buffer)
		pem.Encode(caPEM, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		})
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(caPEM.Bytes())
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to write CA certificate: %v", err), http.StatusInternalServerError)
			return
		}
		slog.Info("Served CA certificate", "size", len(caPEM.Bytes()), "type", "application/x-pem-file")
	})
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
