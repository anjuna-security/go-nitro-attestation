package attester

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

var (
	address = "http://localhost:50123"
)

// GetAttestationReport requests an attestation document from an HTTP endpoint local to the enclave
// Accepts an user data buffer to be included in the attestation document
// The user data buffer cannot be larger than attestdoc.MAX_USER_DATA_SIZE_BYTES bytes (1024 bytes)
func GetAttestationReport(userData []byte) (io.ReadCloser, error) {
	var req struct {
		UserData []byte `json:"user_data"`
	}

	req.UserData = userData
	payload, _ := json.Marshal(&req)
	resp, err := http.Post(address, "application/json", bytes.NewReader(payload))

	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}
