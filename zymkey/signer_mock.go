//go:build !zymkey

package zymkey

// NewSigner creates a new mock signer.
func NewSigner(slot Slot) (Signer, error) {
	return NewMockSigner(slot)
}