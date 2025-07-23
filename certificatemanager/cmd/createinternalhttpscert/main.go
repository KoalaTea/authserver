package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
	"zymkeystuff/signer"
)

func main() {
	// Step 1: Generate a new ECDSA key for the HTTPS cert (not in Zymkey)
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Errorf("failed to generate leaf private key: %w", err))
	}

	// Step 2: Create CSR template
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "www.testing.internal",
		},
		DNSNames: []string{"www.testing.internal"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		panic(fmt.Errorf("failed to create CSR: %w", err))
	}

	// Step 3: Parse CSR back
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		panic(fmt.Errorf("failed to parse CSR: %w", err))
	}
	if err := csr.CheckSignature(); err != nil {
		panic(fmt.Errorf("CSR signature invalid: %w", err))
	}

	// Step 4: Load CA certificate
	caCertPEM, err := os.ReadFile("ca_cert.pem")
	if err != nil {
		panic(fmt.Errorf("could not read CA cert: %w", err))
	}
	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		panic("invalid CA PEM block")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		panic(fmt.Errorf("could not parse CA certificate: %w", err))
	}

	// Step 5: Load Zymkey signer
	signer, err := signer.NewZymkeySigner(0)
	if err != nil {
		panic(fmt.Errorf("failed to init Zymkey signer: %w", err))
	}

	// Step 6: Create HTTPS leaf certificate
	leafCert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
	}

	// Step 7: Sign the CSR using the Zymkey-backed CA
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafCert, caCert, csr.PublicKey, signer)
	if err != nil {
		panic(fmt.Errorf("failed to sign certificate: %w", err))
	}

	// Step 8: Save outputs
	savePEM("leaf_cert.pem", "CERTIFICATE", leafCertDER)
	savePEM("leaf_key.pem", "EC PRIVATE KEY", x509.MarshalECPrivateKeyOrPanic(privKey))

	fmt.Println("✅ Certificate created for https://www.testing.internal")
}

func savePEM(filename string, blockType string, derBytes []byte) {
	file, err := os.Create(filename)
	if err != nil {
		panic(fmt.Errorf("failed to create %s: %w", filename, err))
	}
	defer file.Close()

	pem.Encode(file, &pem.Block{Type: blockType, Bytes: derBytes})
}

// Utility for errorless key marshaling
func x509MarshalECPrivateKeyOrPanic(key *ecdsa.PrivateKey) []byte {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(fmt.Errorf("cannot marshal EC private key: %w", err))
	}
	return der
}
