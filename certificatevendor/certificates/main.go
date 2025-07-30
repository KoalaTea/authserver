package certificates

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/big"
	"os"
	"time"

	"github.com/koalatea/authserver/certificatevendor/serial"
	"github.com/koalatea/authserver/zymkey"
)

type CertProvider struct {
	serial            *serial.Serial
	signer            crypto.Signer
	ca                *x509.Certificate
	serverCertificate *x509.Certificate
}

func New() (*CertProvider, error) {
	signer, err := zymkey.NewSigner(zymkey.Slot0)
	if err != nil {
		return nil, err
	}

	serialNum, err := serial.New()
	if err != nil {
		return nil, err
	}

	ca, err := getCA(signer, serialNum)
	if err != nil {
		return nil, err
	}
	serverCert, err := genAuthCerts(ca, signer, serialNum)
	if err != nil {
		return nil, err
	}

	return &CertProvider{
		serial:            serialNum,
		signer:            signer,
		ca:                ca,
		serverCertificate: serverCert,
	}, nil
}

func (cp *CertProvider) CA() *x509.Certificate {
	return cp.ca
}

func (cp *CertProvider) ServerCert() *tls.Certificate {
	return &tls.Certificate{
		Certificate: [][]byte{cp.serverCertificate.Raw},
		PrivateKey:  cp.signer,
		Leaf:        cp.serverCertificate,
	}
}

func getCA(signer *zymkey.Signer, serialNum *serial.Serial) (*x509.Certificate, error) {
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

	caSerial, err := serialNum.NextSerial()
	if err != nil {
		return nil, err
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(caSerial),
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
		return nil, errors.New("zymkey signer was not an ecdsa publickey")
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

func writePem(path string, block *pem.Block) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("failed to create file %s: %v", path, err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		log.Fatalf("failed to write PEM to %s: %v", path, err)
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func removeIfExists(paths ...string) {
	for _, path := range paths {
		if fileExists(path) {
			os.Remove(path)
		}
	}
}

func genAuthCerts(ca *x509.Certificate, caSigner crypto.Signer, serialNum *serial.Serial) (*x509.Certificate, error) {
	os.MkdirAll("vendorauth", 0700)
	// === Server cert ===
	var serverCertificate *x509.Certificate
	serverCertPath := "vendorauth/server.pem"
	// serverKeyPath := "vendorauth/server.key"
	// if !fileExists(serverCertPath) || !fileExists(serverKeyPath) {
	if !fileExists(serverCertPath) {
		log.Println("Generating new server certificate because either the key and/or certificate are missing...")
		// removeIfExists(serverCertPath, serverKeyPath)
		removeIfExists(serverCertPath)

		serverCertSerial, err := serialNum.NextSerial()
		if err != nil {
			return nil, err
		}
		// serverPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serverTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(serverCertSerial),
			Subject: pkix.Name{
				CommonName: "certificatevendor",
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(1, 0, 0),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature,
		}
		pubKey, ok := caSigner.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("zymkey signer was not an ecdsa publickey")
		}
		serverBytes, _ := x509.CreateCertificate(rand.Reader, serverTemplate, ca, pubKey, caSigner)
		writePem(serverCertPath, &pem.Block{Type: "CERTIFICATE", Bytes: serverBytes})
		serverCertificate, err = x509.ParseCertificate(serverBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created server certificate: %w", err)
		}
	} else {
		slog.Info("Server certificate exists, loading", "path", serverCertPath)
		pemData, err := os.ReadFile(serverCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read server cert file: %w", err)
		}
		block, _ := pem.Decode(pemData)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("failed to decode PEM block containing server certificate")
		}
		serverCertificate, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server certificate: %w", err)
		}
	}

	// === Client cert ===
	clientCertPath := "vendorauth/client.pem"
	clientKeyPath := "vendorauth/client.key"
	if !fileExists(clientCertPath) || !fileExists(clientKeyPath) {
		log.Println("Generating new client certificate because either the key and/or certificate are missing......")
		removeIfExists(clientCertPath, clientKeyPath)

		clientCertSerial, err := serialNum.NextSerial()
		if err != nil {
			return nil, err
		}
		clientPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		clientTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(clientCertSerial),
			Subject: pkix.Name{
				CommonName: "certificatevendor-client",
			},
			NotBefore:   time.Now(),
			NotAfter:    time.Now().AddDate(1, 0, 0),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature,
		}
		clientBytes, _ := x509.CreateCertificate(rand.Reader, clientTemplate, ca, &clientPriv.PublicKey, caSigner)
		writePem(clientCertPath, &pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
		clientPrivBytes, _ := x509.MarshalECPrivateKey(clientPriv)
		writePem("vendorauth/client.key", &pem.Block{Type: "EC PRIVATE KEY", Bytes: clientPrivBytes})
	}

	log.Println("Certificates generated in vendorauth/")

	return serverCertificate, nil
}

// create a new user certificate using the provided username and public key signed by the CA
func (cp *CertProvider) NewUserCert(username string, pemPubKey string) (*x509.Certificate, error) {
	serialNumber, err := cp.serial.NextSerial()
	if err != nil {
		return nil, fmt.Errorf("failed to get next serial number: %w", err)
	}

	serialNumberBig := big.NewInt(serialNumber)

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

	serialNumberBig := big.NewInt(serialNumber)

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

	serialNumberBig := big.NewInt(serialNumber)

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
