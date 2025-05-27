package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/anjuna-security/go-nitro-attestation/attester"
)

func main() {
	// Fresh ECDSA P-384 key pair; public key will appear in the report.
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKeyDer, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		panic(err)
	}

	// Application-specific payload to be signed.
	data := []byte("Hello World!")

	// 16-byte challenge nonce from the relying service (prevents replay).
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		panic(err)
	}

	// Request attestation document (each parameter is optional).
	docReader, err := attester.GetAttestationReport(publicKeyDer, data, nonce)
	if err != nil {
		panic(err)
	}

	// Remember to close the returned stream.
	defer docReader.Close()

	// Read and print the document (hex) for demo; normally send to verifier.
	docBytes, _ := io.ReadAll(docReader)
	fmt.Println(hex.EncodeToString(docBytes))
}
