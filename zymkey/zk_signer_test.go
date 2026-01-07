package zymkey

import "crypto"

var _ crypto.Signer = ZymkeySigner{}
