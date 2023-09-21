package attester

import (
	"encoding/base64"
	"io"
	"net/http"
)

var (
	address = "http://localhost:50123"
)

// GetAttestationReport requests an attestation document from an HTTP endpoint local to the enclave
// Accepts an user data byte array to be included in the attestation document
// The user data buffer cannot be larger than attestdoc.MAX_USER_DATA_SIZE_BYTES bytes (1024 bytes)
func GetAttestationReport(userData []byte) (io.ReadCloser, error) {
	data := base64.URLEncoding.EncodeToString(userData)
	resp, err := http.Get(address + "/api/v1/attestation/report?userData=" + data)

	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}
