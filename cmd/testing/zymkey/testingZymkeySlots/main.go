package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/koalatea/authserver/zymkey"
)

func publicKeysEqual(a, b *ecdsa.PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}

	// Compare curve (pointer comparison is valid here)
	if a.Curve != b.Curve {
		return false
	}

	// Compare X and Y values
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

type ecdsaSignature struct {
	R, S *big.Int
}

// SignAndVerify signs the given data using the signer and verifies it using the provided public key.
// Returns true if valid, false otherwise.
func SignAndVerify(signer crypto.Signer, pub *ecdsa.PublicKey, data []byte) (bool, error) {
	// Hash the data
	hash := sha256.Sum256(data)

	// Sign the hash
	sig, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		return false, err
	}

	// Decode ASN.1 DER signature
	var esig ecdsaSignature
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		return false, errors.New("failed to parse ECDSA signature")
	}

	// Verify the signature
	isValid := ecdsa.Verify(pub, hash[:], esig.R, esig.S)
	return isValid, nil
}

func main() {
	signer0, err := zymkey.NewSigner(zymkey.Slot0)
	if err != nil {
		log.Fatalf("Failed to make Signer for Slot0: %v", err)
	}
	signer1, err := zymkey.NewSigner(zymkey.Slot1)
	if err != nil {
		log.Fatalf("Failed to make Signer for Slot1: %v", err)
	}
	signer2, err := zymkey.NewSigner(zymkey.Slot2)
	if err != nil {
		log.Fatalf("Failed to make Signer for Slot2: %v", err)
	}
	key0 := signer0.Public().(*ecdsa.PublicKey)
	key1 := signer1.Public().(*ecdsa.PublicKey)
	key2 := signer2.Public().(*ecdsa.PublicKey)

	if key0 == nil || key1 == nil || key2 == nil {
		log.Fatal("One or more keys are nil")
	}
	if !publicKeysEqual(key0, key1) && !publicKeysEqual(key0, key2) && !publicKeysEqual(key1, key2) {
		log.Fatal("All keys are different")
	} else {
		log.Println("Some keys are the same")
	}

	ok, err := SignAndVerify(signer0, key0, []byte("important message"))
	if err != nil {
		fmt.Println("Slot 0 Sign Verification Error:", err)
	} else {
		fmt.Println("Slot 0 Signature valid?", ok)
	}
	ok, err = SignAndVerify(signer1, key1, []byte("important message"))
	if err != nil {
		fmt.Println("Slot 1 Sign Verification Error:", err)
	} else {
		fmt.Println("Slot 1 Signature valid?", ok)
	}
	ok, err = SignAndVerify(signer2, key2, []byte("important message"))
	if err != nil {
		fmt.Println("Slot 2 Sign Verification Error:", err)
	} else {
		fmt.Println("Slot 2 Signature valid?", ok)
	}
}
