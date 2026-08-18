//go:build zymkey

package zymkey

// NewSigner creates a new zymkey signer, falling back to an in-memory mock signer if zymkey hardware is unavailable.
func NewSigner(slot Slot) (Signer, error) {
	s, err := NewZymkeySigner(slot)
	if err == nil {
		return s, nil
	}
	return NewMockSigner(slot)
}
