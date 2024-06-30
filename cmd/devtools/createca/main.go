package main

import (
	"fmt"

	"github.com/koalatea/authserver/server/certificates"
	"github.com/koalatea/authserver/server/ent"
)

func main() {
	graph, _ := ent.Open("sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	_, err := certificates.NewCertProvider(graph)
	if err != nil {
		fmt.Errorf("%w", err)
	}
}
