package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
)

func main() {
	server := &http.Server{
		Addr: ":4433",
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello from Zymkey-signed HTTPS cert!")
	})

	log.Println("Serving HTTPS at https://www.testing.internal:4433")
	log.Fatal(server.ListenAndServeTLS("leaf_cert.pem", "leaf_key.pem"))
}
