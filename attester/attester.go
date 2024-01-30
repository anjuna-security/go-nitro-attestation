package attester

import (
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
)

var (
	address = "http://localhost:50123"
)

// GetAttestationReport requests an attestation document from an HTTP endpoint local to the enclave
// Accepts an user data byte array to be included in the attestation document
// The user data buffer cannot be larger than attestdoc.MAX_USER_DATA_SIZE_BYTES bytes (1024 bytes)
// publicKey can be any of the structure types accepted by x509.MarshalPKIXPublicKey(),
// including: *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey (not a pointer), and *ecdh.PublicKey
func GetAttestationReport(publicKey any, userData []byte, nonce []byte) (io.ReadCloser, error) {
	url := address + "/api/v1/attestation/report"

	var params []string

	if len(userData) > 0 {
		params = append(params, "userData="+base64.URLEncoding.EncodeToString(userData))
	}

	if publicKey != nil {
		derBlob, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, err
		}

		params = append(params, "publicKey="+base64.URLEncoding.EncodeToString(derBlob))
	}

	if len(nonce) > 0 {
		params = append(params, "nonce="+base64.URLEncoding.EncodeToString(nonce))
	}

	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}
