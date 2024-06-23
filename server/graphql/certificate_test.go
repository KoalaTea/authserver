package graphql_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
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

func TestRequestCertMutation(t *testing.T) {
	ctx := context.Background()
	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	defer graph.Close()
	c, _ := certificates.NewCertProvider(graph)
	// srv := auth.AuthDisabledMiddleware(handler.NewDefaultServer(graphql.NewSchema(graph)), graph)
	routes := authServerHttp.RouteMap{}
	routes.Handle("/graphql", handler.NewDefaultServer(graphql.NewSchema(graph, c)))
	router := testingutils.NewRouter(routes, graph)
	gqlClient := client.New(router, client.Path("/graphql"))

	mut := `
	mutation requestCert($target: String!, $pubkey: String!) {
		requestCert(target: $target, pubKey:$pubkey)
	}
	`

	// TODO gen key here
	createCert := func() (string, error) {
		var resp struct {
			RequestCert string
		}
		err := gqlClient.Post(mut, &resp,
			client.Var("target", "aaaa"),
			client.Var("pubkey", "aaaa"),
		)
		if err != nil {
			return "", err
		}
		return resp.RequestCert, nil
	}

	// Check cert here
	certPEM, err := createCert()
	if err != nil {
		t.Errorf("Creating Cert graphql mutation errored with: %+v", err)
		return
	}
	if certPEM == "" {
		t.Error("Request cert was empty")
		return
	}
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

	trackedCert, err := graph.Cert.Query().First(ctx)
	if err != nil {
		t.Errorf("Failed to get the tracked cert created using requestCert mutation from the Database with: %+v", err)
	}

	if cert.SerialNumber.Uint64() != uint64(trackedCert.ID) {
		t.Errorf("requestCert certs serialnumber does not match the id of the certificate tracked in the database %s != %d", cert.SerialNumber, trackedCert.ID)
	}

}
