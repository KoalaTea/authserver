package zymkey

import (
	"crypto"
	"io"
)

// Signer is an interface that abstracts the crypto.Signer interface.
type Signer interface {
	Public() crypto.PublicKey
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	Close() error
}

type Slot int

const (
	Slot0 Slot = iota
	Slot1
	Slot2
)