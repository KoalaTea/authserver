package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/koalatea/authserver/server/ent"
	"github.com/koalatea/authserver/server/ent/migrate"
	_ "github.com/mattn/go-sqlite3"
)

// Creating an x509 certificate requires a serialnumber which needs to be unique within a CA
// I was planning to use the ID of the Cert ent but the ent has to be created before it gets an id
// and to be created it needs the x509 cert in pem format
// Using the count of certificates brings us into the territory of needing transactions for creation.
// In the same way an ID does tbh.
// random and just return an error and on the client side we can retry

// Locking moments
// On creating a certificate with count approach we want to lock the entire certificate table to ensure atomicity accross the creation of a certificate
// But only after we validate the inputs and fields. A failed certificate creation can still avoid making any actual certificates.

// With an incrimental tracker of serialnumbers as an individual table and row with the currentserialnumber field we would lock query add one save
// we can also associate that with CAs at some point potentially.

// Other things
// Once a certificate is revoked the field should be immutable

// Questions
// If I have an incremental field using sql.Annotations when I use Add(1) do I get the new integer back?
// Is incremental actually just an auto incement on the field on creation?
// And can that race condition or is that quaranteed safe?
// How can I properly retry locks in ent?
// How can I await a lock in ent?

// Some page tracking
// https://entgo.io/ja/blog/2021/07/22/database-locking-techniques-with-ent/
// https://github.com/ent/ent/issues/2448
// https://sqlite.org/isolation.html
// https://en.wikipedia.org/wiki/Isolation_(database_systems)

func main() {
	ctx := context.Background()
	graph, _ := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	if err := graph.Schema.Create(
		context.Background(),
		migrate.WithGlobalUniqueID(true),
	); err != nil {
		log.Printf("failed to initialize graph schema: %s", err)
	}
	_, err := graph.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		fmt.Printf("couldnt begin TX %+v\n", err)
	}
	count, err := graph.Cert.Query().Count(ctx)
	if err != nil {
		fmt.Printf("couldnt get count of Certs %+v\n", err)
	}
	fmt.Printf("Got a count %d\n", count)
}
