package graphql

import (
	"crypto"

	"github.com/99designs/gqlgen/graphql"
	"github.com/koalatea/authserver/certificatevendor/graphql/generated"
	"github.com/koalatea/authserver/certificatevendor/serial"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	serial *serial.Serial
	signer crypto.Signer
}

func NewSchema(s *serial.Serial, signer crypto.Signer) graphql.ExecutableSchema {
	return generated.NewExecutableSchema(generated.Config{
		Resolvers: &Resolver{s, signer},
	})
}
