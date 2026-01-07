package graphql

import (
	"github.com/99designs/gqlgen/graphql"
	"github.com/koalatea/authserver/certificatevendor/certificates"
	"github.com/koalatea/authserver/certificatevendor/graphql/generated"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	certificates *certificates.CertProvider
}

func NewSchema(certs *certificates.CertProvider) graphql.ExecutableSchema {
	return generated.NewExecutableSchema(generated.Config{
		Resolvers: &Resolver{certificates: certs},
	})
}
