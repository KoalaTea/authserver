package graphql

import (
	"github.com/99designs/gqlgen/graphql"
	"github.com/koalatea/authserver/server/certificates"
	"github.com/koalatea/authserver/server/ent"
	"github.com/koalatea/authserver/server/graphql/generated"
	"go.opentelemetry.io/otel"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

var tracer = otel.Tracer("authserver/graphql")

type Resolver struct {
	client       *ent.Client
	certProvider *certificates.CertProvider
}

func NewSchema(client *ent.Client, certProvider *certificates.CertProvider) graphql.ExecutableSchema {
	return generated.NewExecutableSchema(generated.Config{
		Resolvers: &Resolver{client, certProvider},
	})
}
