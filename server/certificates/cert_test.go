package certificates

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/koalatea/authserver/server/ent/enttest"
	internalHttp "github.com/koalatea/authserver/server/internal/http"
	_ "github.com/mattn/go-sqlite3"
)

func TestNewCertProviderInMemoryDefaults(t *testing.T) {
	provider, err := NewCertProvider(nil)
	if err != nil {
		t.Fatalf("Failed to create in-memory cert provider: %v", err)
	}
	if provider == nil || provider.ca == nil || provider.key == nil {
		t.Fatal("Expected non-nil provider, CA certificate, and private key")
	}
	if !provider.ca.IsCA {
		t.Error("Expected generated certificate to be a CA")
	}
}

func TestNewCertProviderWithCustomCAAndKey(t *testing.T) {
	// Generate custom CA and key for testing
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to gen key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1234),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	caBuf := new(bytes.Buffer)
	pem.Encode(caBuf, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	keyBuf := new(bytes.Buffer)
	pem.Encode(keyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	t.Run("from PEM strings", func(t *testing.T) {
		provider, err := NewCertProvider(nil, caBuf.String(), keyBuf.String())
		if err != nil {
			t.Fatalf("Failed with custom PEM strings: %v", err)
		}
		if provider.ca.SerialNumber.Int64() != 1234 {
			t.Errorf("Expected serial number 1234, got %d", provider.ca.SerialNumber.Int64())
		}
	})

	t.Run("from file paths", func(t *testing.T) {
		tmpDir := t.TempDir()
		caPath := filepath.Join(tmpDir, "ca.pem")
		keyPath := filepath.Join(tmpDir, "key.pem")
		os.WriteFile(caPath, caBuf.Bytes(), 0644)
		os.WriteFile(keyPath, keyBuf.Bytes(), 0644)

		provider, err := NewCertProvider(nil, caPath, keyPath)
		if err != nil {
			t.Fatalf("Failed with file paths: %v", err)
		}
		if provider.ca.SerialNumber.Int64() != 1234 {
			t.Errorf("Expected serial number 1234, got %d", provider.ca.SerialNumber.Int64())
		}
	})
}

func TestRevocationCrl(t *testing.T) {
	ctx := context.Background()
	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	provider, err := NewCertProvider(graph)
	if err != nil {
		t.Fatalf("Failed to create cert provider: %v", err)
	}
	routes := Endpoints(provider)
	router := internalHttp.NewServer(routes, internalHttp.WithAuthenticationBypass(graph))
	w := httptest.NewRecorder()

	cert := graph.Cert.Create().SetPem("").SetSerialNumber(int64(1)).SaveX(ctx)
	err = provider.RevokeCertificate(ctx, int64(cert.ID))
	if err != nil {
		t.Fatalf("Failed to revoke test cert: %v", err)
	}

	r, _ := http.NewRequest("GET", "/certs/crl", nil)
	router.ServeHTTP(w, r)
	body, _ := ioutil.ReadAll(w.Body)
	// Decode the PEM block
	block, _ := pem.Decode(body)
	if block == nil {
		t.Fatalf("Failed to decode returned crl PEM block")
	}

	// Parse the DER-encoded CRL
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse returned CRL from endpoint: %v", err)
	}
	if crl.Number.Int64() != int64(1) {
		t.Fatalf("CRL does not have the revoked cert in it crl.Number: %d", crl.Number.Int64())
	}
	if crl.RevokedCertificateEntries[0].SerialNumber.Int64() != cert.SerialNumber {
		t.Fatal("CRL revoked certificate does not match the test certificates ID")
	}
}
