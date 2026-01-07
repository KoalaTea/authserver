// vendorauth/client.go
package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	// Load client cert and key
	cert, err := tls.LoadX509KeyPair("vendorauth/client.pem", "vendorauth/client.key")
	if err != nil {
		log.Fatalf("Failed to load client cert: %v", err)
	}

	// Load CA cert to verify server
	caCert, err := os.ReadFile("vendorauth/ca.pem")
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	// TLS config for client
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: false, // verify server
		MinVersion:         tls.VersionTLS13,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	resp, err := client.Get("https://localhost:8443/secure")
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	log.Println("Server replied:", string(body))
}
