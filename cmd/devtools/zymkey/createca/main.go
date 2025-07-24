package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/koalatea/authserver/zymkey"
)

func main() {
	// Generate key in Zymkey slot 0
	signer, err := zymkey.NewSigner(0)
	if err != nil {
		panic(fmt.Errorf("Zymkey signer error: %w", err))
	}

	pubKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		panic("invalid public key type")
	}

	// Certificate template for a CA
	template := &x509.Certificate{
		SerialNumber: big.NewInt(20250723),
		Subject: pkix.Name{
			Organization:  []string{"Zymbit Secure CA"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"Santa Barbara"},
			StreetAddress: []string{"123 Crypto Way"},
			PostalCode:    []string{"93101"},
			CommonName:    "Zymkey Root CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0), // 10 years

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Create a self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, signer)
	if err != nil {
		panic(fmt.Errorf("certificate creation failed: %w", err))
	}

	// Write the certificate as PEM
	certFile, err := os.Create("ca_cert.pem")
	if err != nil {
		panic(err)
	}
	defer certFile.Close()

	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fmt.Println("✅ Self-signed CA certificate created: ca_cert.pem")
}
