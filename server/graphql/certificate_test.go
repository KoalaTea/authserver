package graphql_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"

	"github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/koalatea/authserver/server/certificates"
	"github.com/koalatea/authserver/server/ent/enttest"
	"github.com/koalatea/authserver/server/graphql"
	authServerHttp "github.com/koalatea/authserver/server/http"
	"github.com/koalatea/authserver/server/testingutils"

	_ "github.com/mattn/go-sqlite3"
)

func pubKeyToPem(pubKey *rsa.PublicKey) string {
	// Convert the RSA public key to PEM format
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubKey),
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes)
}

func TestRequestCertMutation(t *testing.T) {
	ctx := context.Background()
	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer graph.Close()
	c, _ := certificates.NewCertProvider(graph)
	routes := authServerHttp.RouteMap{}
	routes.Handle("/graphql", handler.NewDefaultServer(graphql.NewSchema(graph, c)))
	router := testingutils.NewRouter(routes, graph)
	gqlClient := client.New(router, client.Path("/graphql"))

	mut := `
	mutation requestCert($target: String!, $pubkey: String!) {
		requestCert(target: $target, pubKey:$pubkey)
	}
	`

	testingUsername := "testinguser"
	// Generate an example RSA public/private key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Error generating RSA key: %v\n", err)
		return
	}
	pubKey := pubKeyToPem(&privateKey.PublicKey)

	createCert := func() (string, error) {
		var resp struct {
			RequestCert string
		}
		err := gqlClient.Post(mut, &resp,
			client.Var("target", testingUsername),
			client.Var("pubkey", pubKey),
		)
		if err != nil {
			return "", err
		}
		return resp.RequestCert, nil
	}

	// create the Certificate
	certPEM, err := createCert()

	// Verify that creating the certificate worked
	if err != nil {
		t.Errorf("Creating Cert graphql mutation errored with: %+v", err)
		return
	}
	if certPEM == "" {
		t.Error("Request cert was empty")
		return
	}

	// TODO returns
	// Convert to x509 certificate
	// Step 2: Decode the PEM block
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Errorf("failed to decode PEM block containing the certificate")
	}
	// Step 3: Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Errorf("failed to parse certificate: %v", err)
	}

	// Verify the fields of the certificate
	trackedCert, err := graph.Cert.Query().First(ctx)
	if err != nil {
		t.Errorf("Failed to get the tracked cert created using requestCert mutation from the Database with: %+v", err)
	}
	if cert.SerialNumber.Int64() != int64(trackedCert.SerialNumber) {
		t.Errorf("requestCert certs serialnumber does not match the id of the certificate tracked in the database %s != %d", cert.SerialNumber, trackedCert.ID)
	}
	if cert.Subject.CommonName != testingUsername {
		t.Errorf("requestCert created certificate CommonName does not match the requested target %s != %s", cert.Subject.CommonName, testingUsername)
	}
	certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Errorf("requestCert created cert PublicKey was not an rsa.PublicKey")
	}
	// Compare the public keys
	// TODO how to properly show they dont match? x != y printing
	if !publicKeysMatch(certPubKey, &privateKey.PublicKey) {
		t.Error("requestCert created cert PublicKey does not match requested public key")
	}
}

func publicKeysMatch(key1, key2 *rsa.PublicKey) bool {
	return reflect.DeepEqual(key1, key2)
}

func TestRevokeCertMutation(t *testing.T) {
	ctx := context.Background()
	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer graph.Close()
	c, _ := certificates.NewCertProvider(graph)
	routes := authServerHttp.RouteMap{}
	routes.Handle("/graphql", handler.NewDefaultServer(graphql.NewSchema(graph, c)))
	router := testingutils.NewRouter(routes, graph)
	gqlClient := client.New(router, client.Path("/graphql"))
	graph.Cert.Create().SetPem("").SetSerialNumber(int64(1)).SaveX(ctx)

	mut := `
	mutation revokeCert($serialNumber: String!) {
		revokeCert(serialNumber:$serialNumber)
	}
	`
	revokeCert := func() (bool, error) {
		var resp struct {
			RevokeCert bool
		}
		err := gqlClient.Post(mut, &resp,
			client.Var("serialNumber", "1"),
		)
		if err != nil {
			return false, err
		}
		return resp.RevokeCert, nil
	}

	success, err := revokeCert()
	if err != nil {
		t.Errorf("Failed to revoked cert with error %+v", err)
	}
	if success != true {
		t.Error("Failed to revoke cert revokeCert returned false")
	}
	cert, err := graph.Cert.Query().First(ctx)
	if err != nil {
		t.Errorf("Failed to get the test cert with error %+v", err)
	}
	if cert.Revoked != true {
		t.Error("Test cert has revoked false after revokeCert call")
	}
}
