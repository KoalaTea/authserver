package certificates

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/koalatea/authserver/server/ent"
)

type CertProvider struct {
	ca    *x509.Certificate
	key   *rsa.PrivateKey
	graph *ent.Client
}

// generateRandomInt64 generates a random int64 value using crypto/rand
func generateRandomInt64() (int64, error) {
	// Create a big.Int with the maximum value for int64
	max := big.NewInt(1<<63 - 1)

	// Generate a random big.Int value between 0 and max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}

	// Convert the big.Int value to int64
	return n.Int64(), nil
}

func loadOrReadPem(input string) ([]byte, error) {
	if _, err := os.Stat(input); err == nil {
		return os.ReadFile(input)
	}
	return []byte(input), nil
}

func parseCACert(caInput string) (*x509.Certificate, error) {
	bytes, err := loadOrReadPem(caInput)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate input: %w", err)
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}
	return cert, nil
}

func parseCAPrivKey(keyInput string) (*rsa.PrivateKey, error) {
	bytes, err := loadOrReadPem(keyInput)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key input: %w", err)
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from CA private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key as PKCS1 or PKCS8: %w", err)
	}
	rsaKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsed private key is not an RSA private key")
	}
	return rsaKey, nil
}

// NewCertProvider creates a CertProvider. If caCert and caPrivKey are provided (as file paths or PEM strings),
// they will be used. Otherwise, a CA and RSA private key will be generated in-memory.
func NewCertProvider(graph *ent.Client, caOpts ...string) (*CertProvider, error) {
	var caCertInput, caPrivKeyInput string
	if len(caOpts) > 0 {
		caCertInput = caOpts[0]
	}
	if len(caOpts) > 1 {
		caPrivKeyInput = caOpts[1]
	}

	if caCertInput != "" && caPrivKeyInput != "" {
		ca, err := parseCACert(caCertInput)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA cert: %w", err)
		}
		caPrivKey, err := parseCAPrivKey(caPrivKeyInput)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA private key: %w", err)
		}
		return &CertProvider{ca: ca, key: caPrivKey, graph: graph}, nil
	}

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		SubjectKeyId:          []byte("temps"),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	// Gen private key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// Create Cert
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	// Parse back generated certificate bytes to ensure full certificate structure
	parsedCA, err := x509.ParseCertificate(caBytes)
	if err == nil {
		ca = parsedCA
	}

	provider := &CertProvider{ca: ca, key: caPrivKey, graph: graph}
	return provider, nil
}

// Convert a PEM encoded public key string to rsa.PublicKey
func pemToPublicKey(pemStr string) (*rsa.PublicKey, error) {
	// Decode the PEM block
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	// Parse the DER-encoded public key
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: %v", err)
	}

	return pub, nil
}

func (p *CertProvider) CreateCertificate(ctx context.Context, target string, pemPubKey string) (string, error) {
	serialNumber, err := generateRandomInt64()
	if err != nil {
		return "", fmt.Errorf("error generating random int64 for serialNumber: %w", err)
	}
	// create cert to sign
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			CommonName: target,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	pubKey, err := pemToPublicKey(pemPubKey)
	if err != nil {
		return "", err
	}

	// sign cert with the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, p.ca, pubKey, p.key)
	if err != nil {
		return "", err
	}

	// PEMENCODE Cert
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	createdCert, err := p.graph.Cert.Create().SetPem(certPEM.String()).SetSerialNumber(cert.SerialNumber.Int64()).Save(ctx)
	if err != nil {
		return "", err
	}

	return createdCert.Pem, nil
}

func NewCertProviderFromFiles(caPrivKeyLoc string, caCertLoc string) (*CertProvider, error) {
	return NewCertProvider(nil, caCertLoc, caPrivKeyLoc)
}

func (p *CertProvider) RevokeCertificate(ctx context.Context, serialNumber int64) error {
	cert, err := p.graph.Cert.Get(ctx, int(serialNumber))
	if err != nil {
		return err
	}
	_, err = cert.Update().SetRevoked(true).Save(ctx)
	if err != nil {
		return err
	}

	return nil
}
