package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/koalatea/authserver/zymkey"
)

func main() {
	// Load CSR from file
	csrPem, err := ioutil.ReadFile("csr.pem")
	if err != nil {
		panic(fmt.Errorf("failed to read csr.pem: %w", err))
	}
	csrBlock, _ := pem.Decode(csrPem)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		panic("invalid CSR PEM block")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		panic(fmt.Errorf("failed to parse CSR: %w", err))
	}

	// Validate CSR
	if err := csr.CheckSignature(); err != nil {
		panic(fmt.Errorf("CSR signature invalid: %w", err))
	}

	// Load CA certificate
	caPem, err := ioutil.ReadFile("ca_cert.pem")
	if err != nil {
		panic(fmt.Errorf("failed to read CA cert: %w", err))
	}
	caBlock, _ := pem.Decode(caPem)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		panic("invalid CA certificate PEM block")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		panic(fmt.Errorf("failed to parse CA certificate: %w", err))
	}

	// Use ZymkeySigner in slot 0 (private key is securely held)
	signer, err := zymkey.NewSigner(0)
	if err != nil {
		panic(fmt.Errorf("failed to init Zymkey signer: %w", err))
	}

	// Certificate template (valid for 1 year)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0), // 1 year

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
	}

	// Sign certificate
	leafCertDER, err := x509.CreateCertificate(nil, leaf, caCert, csr.PublicKey, signer)
	if err != nil {
		panic(fmt.Errorf("failed to sign certificate: %w", err))
	}

	// Output leaf cert
	certOut, err := os.Create("leaf_cert.pem")
	if err != nil {
		panic(err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: leafCertDER})
	fmt.Println("✅ HTTPS certificate signed and saved to: leaf_cert.pem")
}
