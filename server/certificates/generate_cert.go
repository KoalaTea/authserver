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
	"io/ioutil"
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

// TODO put certs in common dir or load certs from configuration
func NewCertProvider(graph *ent.Client) (*CertProvider, error) {
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

	// PEM Encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	os.WriteFile("authserverCA.pem", caPEM.Bytes(), 0644)

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	os.WriteFile("authserverCAPrivKey.pem", caPrivKeyPEM.Bytes(), 0644)

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
	// TODO return errors up here

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

// Certificate CN can really be whatever it depends on what is using it on what it needs to be but if everything understands correctly how we use it we will be fine
// other fields may also need to be filled out correctly for the same reason it all depends on what is using it

// TODO maybe options instead

func NewCertProviderFromFiles(caPrivKeyLoc string, caCertLoc string) (*CertProvider, error) {
	cf, e := ioutil.ReadFile(caCertLoc)
	if e != nil {
		return nil, fmt.Errorf("cfload: %w", e)
	}

	kf, e := ioutil.ReadFile(caPrivKeyLoc)
	if e != nil {
		fmt.Println("kfload: %w", e)
	}
	cpb, _ := pem.Decode(cf)
	kpb, _ := pem.Decode(kf)
	crt, e := x509.ParseCertificate(cpb.Bytes)

	if e != nil {
		return nil, fmt.Errorf("parsex509: %w", e)
	}
	key, e := x509.ParsePKCS1PrivateKey(kpb.Bytes)
	if e != nil {
		return nil, fmt.Errorf("parsekey: %w", e)
	}
	return &CertProvider{key: key, ca: crt}, nil
}

func (p *CertProvider) RevokeCertificate(ctx context.Context, serialNumber int64) error {
	// Should this be in the graphql stuff? Want to walk through this with kyle actually
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
