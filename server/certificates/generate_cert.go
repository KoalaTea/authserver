package certificates

import (
	"bytes"
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
)

type CertProvider struct {
	ca  *x509.Certificate
	key *rsa.PrivateKey
}

// TODO put certs in common dir or load certs from configuration
func NewCertProvider() (*CertProvider, error) {
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
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
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

	provider := &CertProvider{ca: ca, key: caPrivKey}
	return provider, nil
}

func (p *CertProvider) CreateCertificate() (string, error) {
	// create cert to sign
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName: "rwhittier",
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Create private key for cert
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", err
	}

	// sign cert with the CA
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, p.ca, &certPrivKey.PublicKey, p.key)
	if err != nil {
		return "", err
	}

	// PEMENCODE Cert
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return certPEM.String(), nil
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
