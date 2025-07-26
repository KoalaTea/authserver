package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
)

const graphqlEndpoint = "http://192.168.1.101:8080/graphql"
const query = `
mutation RequestHTTPSCert($url: String!, $pubkey: String!) {
    requestHTTPSCert(url: $url, pubkey: $pubkey)
}
`

func pubKeyToPem(pubKey *rsa.PublicKey) string {
	// Convert the RSA public key to PEM format
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubKey),
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes)
}

// ECDSA keys maybe?
// // Generate ECDSA key pair
// privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// if err != nil {
//     panic(fmt.Sprintf("Failed to generate private key: %v", err))
// }

// // Convert public key to PEM format
// publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
// if err != nil {
//     panic(fmt.Sprintf("Failed to marshal public key: %v", err))
// }

// publicKeyPEM := &pem.Block{
//     Type:  "PUBLIC KEY",
//     Bytes: publicKeyBytes,
// }
// var publicKeyPEMString strings.Builder
// if err := pem.Encode(&publicKeyPEMString, publicKeyPEM); err != nil {
//     panic(fmt.Sprintf("Failed to encode public key to PEM: %v", err))
// }

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("Error generating RSA key: %v\n", err)
		return
	}
	pubKey := pubKeyToPem(&privateKey.PublicKey)

	// Prepare GraphQL request
	requestBody := fmt.Sprintf(`{
        "query": %q,
        "variables": {
            "url": "www.example.com",
            "pubkey": %q
        }
    }`, query, pubKey)

	// Send request to GraphQL server
	resp, err := http.Post(graphqlEndpoint, "application/json", bytes.NewBufferString(requestBody))
	if err != nil {
		panic(fmt.Sprintf("Failed to send request: %v", err))
	}
	defer resp.Body.Close()

	// Read response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(fmt.Sprintf("Failed to read response: %v", err))
	}

	fmt.Printf("Response: %s\n", string(body))

	// TODO: Save the private key and certificate for future use
}
