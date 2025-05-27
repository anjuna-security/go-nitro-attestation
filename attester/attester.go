package attester

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	address = "http://localhost:50123"
)

// GetAttestationReport requests a signed attestation document from the local enclave HTTP endpoint.
// Optional publicKey, userData, and nonce values can be included in the request.
// Each input must not exceed [attestdoc.MAX_USER_DATA_SIZE_BYTES] (1024 bytes).
// On success, the function returns an io.ReadCloser containing the raw report bytes.
func GetAttestationReport(publicKey, userData, nonce []byte) (io.ReadCloser, error) {
	url := address + "/api/v1/attestation/report"

	var params []string

	if len(publicKey) > 0 {
		params = append(params, "publicKey="+base64.URLEncoding.EncodeToString(publicKey))
	}

	if len(userData) > 0 {
		params = append(params, "userData="+base64.URLEncoding.EncodeToString(userData))
	}

	if len(nonce) > 0 {
		params = append(params, "nonce="+base64.URLEncoding.EncodeToString(nonce))
	}

	if len(params) > 0 {
		url += "?" + strings.Join(params, "&")
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, failedToGetAttestationReport(err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// Success - return the response body
		return resp.Body, nil
	default:
		// Error - read the response body and return an error
		defer resp.Body.Close()
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, failedToGetAttestationReport(fmt.Errorf("%s and error to parse response: %w", resp.Status, err))
		}
		if err, ok := body["error"]; !ok {
			return nil, failedToGetAttestationReport(fmt.Errorf("%s and no error field in response", resp.Status))
		} else {
			return nil, failedToGetAttestationReport(fmt.Errorf("%s: %s", resp.Status, err))
		}
	}
}

func failedToGetAttestationReport(err error) error {
	return fmt.Errorf("failed to get attestation report: %w", err)
}
