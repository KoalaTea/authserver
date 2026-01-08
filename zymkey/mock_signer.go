package zymkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
)

// MockSigner is a mock implementation of the Signer interface for testing.
type MockSigner struct {
	privKey *ecdsa.PrivateKey
}

// NewMockSigner creates a new MockSigner.
func NewMockSigner(slot Slot) (*MockSigner, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MockSigner{privKey: privKey}, nil
}

// Public returns the public key of the mock signer.
func (m *MockSigner) Public() crypto.PublicKey {
	return &m.privKey.PublicKey
}

// Sign signs the given digest with the mock signer.
func (m *MockSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return m.privKey.Sign(rand, digest, opts)
}

// Close does nothing for the mock signer.
func (m *MockSigner) Close() error {
	return nil
}