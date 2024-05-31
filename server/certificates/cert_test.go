package certificates

import "testing"

func TestClientCert(t *testing.T) {
	provider, err := NewCertProvider()
	if err != nil {
		t.Fatalf("%v", err)
	}
	_, err = provider.CreateCertificate()
	if err != nil {
		t.Fatalf("%v", err)
	}
}
