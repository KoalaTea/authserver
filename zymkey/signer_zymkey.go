//go:build zymkey

package zymkey

// NewSigner creates a new zymkey signer.
func NewSigner(slot Slot) (Signer, error) {
	return NewZymkeySigner(slot)
}