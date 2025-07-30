package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"

	"github.com/koalatea/authserver/certificatevendor/certificates"
)

type Server struct {
	Certificates *certificates.CertProvider
	HTTP         *http.Server
	TLSConfig    *tls.Config
}

func getTLSConfig(certProvider *certificates.CertProvider) *tls.Config {
	ca := certProvider.CA()
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca)
	cert := certProvider.ServerCert()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}
	return tlsConfig
}

func RequireClientCertMiddleware(caPool *x509.CertPool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		_, err := cert.Verify(x509.VerifyOptions{
			Roots: caPool,
		})
		if err != nil {
			http.Error(w, "invalid client certificate", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func NewServer() (*Server, error) {
	certs, err := certificates.New()
	if err != nil {
		return nil, err
	}

	tlsConfig := getTLSConfig(certs)

	router := http.NewServeMux()
	router.Handle("/graphql", RequireClientCertMiddleware(tlsConfig.ClientCAs, newGraphqlHandler(certs)))
	router.Handle("/CA", CAHandler(certs))
	httpSrv := &http.Server{
		Addr:      "0.0.0.0:8080",
		Handler:   router,
		TLSConfig: tlsConfig,
	}

	return &Server{
		HTTP:      httpSrv,
		TLSConfig: tlsConfig,
	}, nil
}

func (srv *Server) Run(ctx context.Context) error {
	defer srv.Close()
	slog.InfoContext(ctx, "CertificateVendor HTTP started", "http_addr", srv.HTTP.Addr)
	ln, err := net.Listen("tcp", srv.HTTP.Addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	tlsListener := tls.NewListener(ln, srv.TLSConfig)
	defer tlsListener.Close()
	if err := srv.HTTP.Serve(tlsListener); err != nil {
		return fmt.Errorf("stopped http server: %w", err)
	}
	return nil
}

func (srv *Server) Close() error {
	return srv.HTTP.Shutdown(context.Background())
}
