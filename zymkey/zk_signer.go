package signer

/*
#cgo CFLAGS: -I/usr/include/zymkey
#cgo LDFLAGS: -L/usr/lib -lzk_app_utils
#include <stdlib.h>
#include "zk_app_utils.h"
*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"unsafe"
)

// #cgo LDFLAGS: -L/usr/lib -lzk_app_utils
// #cgo CFLAGS: -I/usr/include/zymkey
// #include <stdbool.h>
// #include <stdlib.h>
// #include "zk_app_utils.h"
import "C"

type ZymkeySigner struct {
	ctx     C.zkCTX
	pubKey  crypto.PublicKey
	keySlot C.int
}

func NewZymkeySigner(slot int) (*ZymkeySigner, error) {
	var ctx C.zkCTX
	rc := C.zkOpen(&ctx)
	if rc != 0 {
		return nil, fmt.Errorf("zkOpen failed: rc=%d", rc)
	}

	var cpubkey *C.uint8_t
	var cpubkeyLen C.int

	rc = C.zkExportPubKey(ctx, &cpubkey, &cpubkeyLen, C.int(slot), C.bool(false))
	if rc != 0 {
		C.zkClose(ctx)
		return nil, fmt.Errorf("zkExportPubKey failed: rc=%d", rc)
	}
	defer C.free(unsafe.Pointer(cpubkey))

	pubBytes := C.GoBytes(unsafe.Pointer(cpubkey), cpubkeyLen)
	if len(pubBytes) != 64 {
		C.zkClose(ctx)
		return nil, fmt.Errorf("unexpected public key length: got %d bytes", len(pubBytes))
	}

	x := new(big.Int).SetBytes(pubBytes[:32])
	y := new(big.Int).SetBytes(pubBytes[32:])

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return &ZymkeySigner{
		ctx:     ctx,
		pubKey:  pubKey,
		keySlot: C.int(slot),
	}, nil
}

func (z *ZymkeySigner) Public() crypto.PublicKey {
	return z.pubKey
}

func (z *ZymkeySigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var sig *C.uint8_t
	var sigLen C.int

	rc := C.zkGenECDSASigFromDigest(z.ctx, (*C.uint8_t)(unsafe.Pointer(&digest[0])), z.keySlot, &sig, &sigLen)
	if rc != 0 {
		return nil, fmt.Errorf("zkGenECDSASigFromDigest failed: rc=%d", rc)
	}
	defer C.free(unsafe.Pointer(sig))

	rawSig := C.GoBytes(unsafe.Pointer(sig), sigLen)
	if len(rawSig) != 64 {
		return nil, fmt.Errorf("unexpected signature length: got %d bytes", len(rawSig))
	}

	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])

	// DER encode the (r, s) pair
	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}

func (z *ZymkeySigner) Close() error {
	if z == nil {
		return fmt.Errorf("ZymkeySigner is nil")
	}

	rc := C.zkClose(z.ctx)
	if rc != 0 {
		return fmt.Errorf("zkClose failed: rc=%d", rc)
	}
	return nil
}
