package certificates

import "testing"

func TestClientCert(t *testing.T) {
	makeCA()
	err := CreateCertificate()
	if err != nil {
		t.Fatalf("%v", err)
	}
}
