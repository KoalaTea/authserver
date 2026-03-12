package zymkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestSigner(t *testing.T) {
	// This will create a MockSigner when the zymkey build tag is not present.
	signer, err := NewSigner(Slot0)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}
	defer signer.Close()

	// Create a digest to sign.
	msg := []byte("hello, world")
	digest := sha256.Sum256(msg)

	// Sign the digest.
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to sign digest: %v", err)
	}

	// Verify the signature.
	pubKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Failed to get public key")
	}

	if !ecdsa.VerifyASN1(pubKey, digest[:], signature) {
		t.Errorf("Signature verification failed")
	}
}