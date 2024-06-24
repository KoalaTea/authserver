package certificates

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koalatea/authserver/server/ent/enttest"
	"github.com/koalatea/authserver/server/testingutils"
	_ "github.com/mattn/go-sqlite3"
)

func TestRevocationCrl(t *testing.T) {
	ctx := context.Background()
	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	provider, err := NewCertProvider(graph)
	if err != nil {
		t.Fatalf("Failed to create cert provider: %v", err)
	}
	routes := Endpoints(provider)
	router := testingutils.NewRouter(routes, graph)
	w := httptest.NewRecorder()

	cert := graph.Cert.Create().SaveX(ctx)
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
	if crl.RevokedCertificateEntries[0].SerialNumber.Int64() != int64(cert.ID) {
		t.Fatal("CRL revoked certificate does not match the test certificates ID")
	}
}
