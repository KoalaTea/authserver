package main

import "crypto"

var _ crypto.Signer = ZymkeySigner{}
