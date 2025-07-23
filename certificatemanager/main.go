package main

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"zymkeystuff/signer"
)

func main() {
	signer, err := signer.NewZymkeySigner(0) // Assuming key is in slot 0
	if err != nil {
		panic(err)
	}

	message := []byte("hello from Zymkey")
	hash := sha256.Sum256(message)

	sig, err := signer.Sign(nil, hash[:], crypto.SHA256)
	if err != nil {
		panic(err)
	}

	fmt.Println("Signature:", hex.EncodeToString(sig))
}
