package graphql_test

import (
	"testing"

	"github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/koalatea/authserver/server/certificates"
	"github.com/koalatea/authserver/server/ent/enttest"
	"github.com/koalatea/authserver/server/graphql"
	_ "github.com/mattn/go-sqlite3"
)

func TestRequestCertMutation(t *testing.T) {
	// ctx := context.Background()
	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	c, _ := certificates.NewCertProvider()
	defer graph.Close()
	// srv := auth.AuthDisabledMiddleware(handler.NewDefaultServer(graphql.NewSchema(graph)), graph)
	srv := handler.NewDefaultServer(graphql.NewSchema(graph, c))
	gqlClient := client.New(srv)

	// Define the mutatation for testing, taking the input as a variable
	mut := `mutation requestCert($target: String!, $pubkey: String!) { requestCert(target: $target, pubKey:$pubkey) }`

	// Make our request to the GraphQL API
	var resp struct {
		RequestCert string
	}
	err := gqlClient.Post(mut, &resp,
		client.Var("target", "aaaa"),
		client.Var("pubkey", "aaaa"),
	)
	if err != nil {
		t.Fatalf("Failed to create cert: %v", err)
	}
	if resp.RequestCert == "" {
		t.Fatal("Request cert returned empty string")
	}
}
