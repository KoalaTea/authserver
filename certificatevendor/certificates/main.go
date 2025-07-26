package certificates

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/koalatea/authserver/certificatevendor/serial"
	"github.com/koalatea/authserver/zymkey"
)

type CertProvider struct {
	serial *serial.Serial
	signer crypto.Signer
	ca     *x509.Certificate
}

func New() (*CertProvider, error) {
	ca, err := getCA()
	if err != nil {
		return nil, err
	}

	signer, err := zymkey.NewSigner(0)
	if err != nil {
		return nil, err
	}

	serialNum, err := serial.New()
	if err != nil {
		return nil, err
	}

	return &CertProvider{
		serial: serialNum,
		signer: signer,
		ca:     ca,
	}, nil
}

func getCA(signer zymkey.Signer) (*x509.Certificate, error) {
	caFilePath := "CA.pem"
	// Check if the file exists
	_, err := os.Stat(caFilePath)
	if err == nil {
		slog.Info("CA exists so loading CA", "path", caFilePath)
		// Read the file
		pemData, err := os.ReadFile(caFilePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read file: %v", err)
		}

		// Decode the PEM block
		block, _ := pem.Decode(pemData)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("failed to decode PEM block containing certificate")
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}

		return cert, nil
	}

	if os.IsNotExist(err) {
		slog.Info("CA does not exist generating one now", "path", caFilePath)
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

	pubKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("zynkey signer was not an ecdsa publickey")
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubKey, signer)
	if err != nil {
		return nil, err
	}

	// PEM Encode
	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	os.WriteFile(caFilePath, caPEM.Bytes(), 0644)

	return ca, nil
}

// create a new user certificate using the provided username and public key signed by the CA
func (cp *CertProvider) NewUserCert(username string, pemPubKey string) (*x509.Certificate, error) {
	serialNumber, err := cp.serial.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get next serial number: %w", err)
	}

	serialNumberBig := big.NewInt(int64(serialNumber))

	cert := &x509.Certificate{
		SerialNumber:          serialNumberBig,
		Subject:               pkix.Name{CommonName: username},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	pubKey, err := pemToPublicKey(pemPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load provided public key PEM: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cp.ca, pubKey, cp.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return x509.ParseCertificate(certBytes)
}

// create a new https server certificate using the provided domain and public key signed by the CA
func (cp *CertProvider) NewHTTPSCert(domain string, pemPubKey string) (*x509.Certificate, error) {
	serialNumber, err := cp.serial.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get next serial number: %w", err)
	}

	serialNumberBig := big.NewInt(int64(serialNumber))

	cert := &x509.Certificate{
		SerialNumber:          serialNumberBig,
		Subject:               pkix.Name{CommonName: domain},
		DNSNames:              []string{domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	pubKey, err := pemToPublicKey(pemPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load provided public key PEM: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cp.ca, pubKey, cp.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return x509.ParseCertificate(certBytes)
}

// Create a new device certificate signe by the CA
func (cp *CertProvider) NewDeviceCert(deviceID string, pemPubKey string) (*x509.Certificate, error) {
	serialNumber, err := cp.serial.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get next serial number: %w", err)
	}

	serialNumberBig := big.NewInt(int64(serialNumber))

	cert := &x509.Certificate{
		SerialNumber:          serialNumberBig,
		Subject:               pkix.Name{CommonName: deviceID},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	pubKey, err := pemToPublicKey(pemPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load provided public key PEM: %w", err)
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cp.ca, pubKey, cp.signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return x509.ParseCertificate(certBytes)
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
