package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/anjuna-security/go-nitro-attestation/attester"
)

func main() {
	// defines your custom data
	myData := []byte("Hello World!")

	// generate RSA-2048 key (optional)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// generate a 12 byte random nonce value
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		panic(err)
	}

	// get a new report byte stream (pass nil to rsaKey parameter if not used)
	docReader, err := attester.GetAttestationReport(rsaKey.PublicKey, myData, nonce)
	if err != nil {
		panic(err)
	}

	docBytes, _ := io.ReadAll(docReader) // read the report's bytes
	fmt.Printf("%x", docBytes)           // print the report's bytes
}
