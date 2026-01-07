package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := "nopush/ntlsauth"
	err := os.MkdirAll(dir, 0700)
	if err != nil {
		log.Fatalf("failed to create dir: %v", err)
	}

	caPath := filepath.Join(dir, "ca.pem")
	serverCertPath := filepath.Join(dir, "server.crt")
	serverKeyPath := filepath.Join(dir, "server.key")
	clientCertPath := filepath.Join(dir, "client.pem")
	clientKeyPath := filepath.Join(dir, "client.key")

	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey

	// Create or read CA
	if exists(caPath) {
		caBytes, _ := ioutil.ReadFile(caPath)
		block, _ := pem.Decode(caBytes)
		caCert, _ = x509.ParseCertificate(block.Bytes)
	} else {
		caCert, caKey = generateCA()
		writeCert(caPath, caCert)
		writeKey(filepath.Join(dir, "ca.key"), caKey)
	}

	// Read or regenerate server keypair
	if !exists(serverCertPath) || !exists(serverKeyPath) {
		if caKey == nil {
			caKey = readKey(filepath.Join(dir, "ca.key"))
		}
		serverCert, serverKey := generateCert("localhost", caCert, caKey, true)
		writeCert(serverCertPath, serverCert)
		writeKey(serverKeyPath, serverKey)
	}

	// Read or regenerate client keypair
	if !exists(clientCertPath) || !exists(clientKeyPath) {
		if caKey == nil {
			caKey = readKey(filepath.Join(dir, "ca.key"))
		}
		clientCert, clientKey := generateCert("test-client", caCert, caKey, false)
		writeCert(clientCertPath, clientCert)
		writeKey(clientKeyPath, clientKey)
	}

	// Load CA cert
	caCertBytes, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Fatalf("failed to read CA file: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertBytes)

	// TLS config: client cert optional, but checked in middleware
	tlsConfig := &tls.Config{
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12,
	}

	// Set up routes
	mux := http.NewServeMux()
	mux.Handle("/graphql", RequireClientCertMiddleware(caCertPool, http.HandlerFunc(graphqlHandler)))
	mux.HandleFunc("/", defaultHandler)

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Println("Server starting on https://localhost:8443")
	log.Fatal(server.ListenAndServeTLS(serverCertPath, serverKeyPath))
}

// --- Cert generation ---

func generateCA() (*x509.Certificate, *rsa.PrivateKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "Example CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	cert, _ := x509.ParseCertificate(certDER)
	return cert, priv
}

func generateCert(commonName string, ca *x509.Certificate, caKey *rsa.PrivateKey, isServer bool) (*x509.Certificate, *rsa.PrivateKey) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	if isServer {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(certDER)
	return cert, priv
}

// --- Cert/Key file I/O ---

func writeCert(path string, cert *x509.Certificate) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	_ = ioutil.WriteFile(path, certPEM, 0644)
}

func writeKey(path string, key *rsa.PrivateKey) {
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	_ = ioutil.WriteFile(path, keyPEM, 0600)
}

func readKey(path string) *rsa.PrivateKey {
	keyBytes, _ := ioutil.ReadFile(path)
	block, _ := pem.Decode(keyBytes)
	key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	return key
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// --- Middleware and Handlers ---
func RequireClientCertMiddleware(caPool *x509.CertPool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}

		cert := r.TLS.PeerCertificates[0]
		log.Printf("Client presented certificate: CN=%s\n", cert.Subject.CommonName)

		opts := x509.VerifyOptions{
			Roots:     caPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // <-- THIS LINE
		}

		if _, err := cert.Verify(opts); err != nil {
			log.Printf("client cert verify failed: %v", err)
			http.Error(w, "invalid client certificate", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func graphqlHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Authenticated access to /graphql")
}

func defaultHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Public access to /")
}
