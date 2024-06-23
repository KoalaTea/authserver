package certificates

import (
	"context"
	"testing"

	"github.com/koalatea/authserver/server/ent/enttest"
)

func TestClientCert(t *testing.T) {
	ctx := context.Background()
	graph := enttest.Open(t, "sqlite3", "file:ent?mode=memory&cache=shared&_fk=1")
	provider, err := NewCertProvider(graph)
	if err != nil {
		t.Fatalf("%v", err)
	}
	_, err = provider.CreateCertificate(ctx)
	if err != nil {
		t.Fatalf("%v", err)
	}
}
