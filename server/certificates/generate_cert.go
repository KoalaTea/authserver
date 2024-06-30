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
	tx, err := p.graph.Tx(ctx)
	if err != nil {
		return "", err
	}
	client := tx.Client()
	// Rollback transaction if we panic
	defer func() {
		if v := recover(); v != nil {
			tx.Rollback()
			panic(v)
		}
	}()
	certCount, err := client.Cert.Query().Count(ctx)
	if err != nil {
		fmt.Printf("%+v", err)
	}

	// create cert to sign
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(certCount)),
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
		tx.Rollback()
		return "", err
	}

	// PEMENCODE Cert
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	createdCert, err := client.Cert.Create().SetPem(certPEM.String()).SetSerialNumber(cert.SerialNumber.Int64()).Save(ctx)
	if err != nil {
		tx.Rollback()
		return "", err
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return "", fmt.Errorf("failed to commit transaction: %w", err)
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
	tx, err := p.graph.Tx(ctx)
	if err != nil {
		return err
	}
	client := tx.Client()
	// Rollback transaction if we panic
	defer func() {
		if v := recover(); v != nil {
			tx.Rollback()
			panic(v)
		}
	}()
	cert, err := client.Cert.Get(ctx, int(serialNumber))
	if err != nil {
		return err
	}
	_, err = cert.Update().SetRevoked(true).Save(ctx)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
