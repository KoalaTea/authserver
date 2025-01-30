package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/go-tpm/tpm2/transport"
)

func main() {
	fmt.Println("testing tpm stuff")
	t, err := transport.OpenTPM()
	if err != nil {
		// if the TPM is not available or not a TPM 2.0, we can skip the PCR extension
		if os.IsNotExist(err) || strings.Contains(err.Error(), "device is not a TPM 2.0") {
			log.Printf("TPM device is not available")

			panic("oops")
		}

		fmt.Printf("error opening TPM device: %w", err)
	}
	fmt.Print("Opened TPM fine")
}

// https://github.com/siderolabs/talos/blob/cf5effabb209fb570f59ba305bdab0b6409c7b93/internal/pkg/rng/tpm.go#L15
// https://github.com/immune-gmbh/guard-oss/blob/14a7c87f4f7d1eaa54105908b637cb98a03800da/apisrv/pkg/evidence/verify.go#L15
// https://noahstride.co.uk/blog/2024-04-10-my-notes-go-and-tpm2/
// https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/protecting_keys_with_the_secure_enclave
// https://github.com/iqlusioninc/keychain-services.rs
// https://www.apple.com/hk/privacy/docs/iOS_Security_Guide_Oct_2014.pdf
// https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web
// https://github.com/ebitengine/purego/blob/main/examples/objc/main_darwin.go
// https://github.com/remko/age-plugin-se/blob/main/Sources/Crypto.swift
// https://github.com/google/go-attestation
