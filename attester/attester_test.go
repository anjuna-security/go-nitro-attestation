package attester

import (
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/sample_prod_doc.bin
var testReport []byte

//go:embed testdata/sample_attestation_doc_full.bin
var sampleAttestationDocFull []byte // Attestation report with user data, public key, and nonce

var (
	sampleAttestationDocFullPubkey = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoiDRmwIE4P15dqsezOZd
GyyaJ+irhcP1kE1MOyChcPVX3Wf0vh7egcHvQLg8bP6VjzY7cesRuC5Mh1fcmtFt
aTaBzB+HW9Rnt5gCaZOBOZFq4Gadn22n7r1Q9VtrLepg9C1YFLiK3XMCD/ATQXKl
XF3RaMyGulTEBi1B2BRFmt17VZ/lyQgtUZ5o1HdpJUjzLDY/xU0L75UdxtPc0ceN
jWp6/GNT/PZBwcmWPGukbTisFyo092W1nPZRDJ1jT4NoVvSoHE1vwCAVeQSxsntM
fBRkLc5MCMAVYbIaImjyRASycd3dkhJ0Irz58sKOzHHDZRnFkk7RsdXnfZqXJa8h
VQIDAQAB
-----END PUBLIC KEY-----`)
)

var (
	sampleAttestationUserData  = []byte("Hello World!\n")
	sampleAttestationUserNonce = []byte("Nonce\n")
)

func TestGetAttestationReport(t *testing.T) {
	expectedData := []byte("")
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b64UserData := r.URL.Query().Get("userData")
			data, err := base64.URLEncoding.DecodeString(b64UserData)
			require.NoError(t, err)
			require.Equal(t, expectedData, data)
			w.Write(testReport)
		}))
	defer server.Close()

	// invalid address
	docReader, err := GetAttestationReport(nil, nil, nil)
	require.Error(t, err)
	require.Nil(t, docReader)

	// valid address
	address = server.URL

	docReader, err = GetAttestationReport(nil, nil, nil)
	require.NoError(t, err)
	require.NotNil(t, docReader)

	doc, err := verifier.NewSignedAttestationReport(docReader)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.NotEmpty(t, doc.Document.PCRs)
	require.NotEmpty(t, doc.Document.PCRs[0])

	// valid user data encoding
	expectedData, _ = base64.StdEncoding.DecodeString("SGVsbG8gV29ybGQhCg==")
	docReader, err = GetAttestationReport(nil, expectedData, nil)
	require.NoError(t, err)

	report, err := verifier.NewSignedAttestationReport(docReader)
	require.NoError(t, err)
	require.NotNil(t, report)

	pcrs := verifier.ConvertPCRsToHex(report.Document.PCRs)
	require.NotEmpty(t, pcrs)

	require.Equal(t, expectedData, report.Document.UserData)
}

func TestGetAttestationReportFull(t *testing.T) {
	expectedPublicKey := []byte{}
	expectedUserData := []byte{}
	expectedUserNonce := []byte{}
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			asn1PublicKey, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("publicKey"))
			require.NoError(t, err)
			require.Equal(t, expectedPublicKey, asn1PublicKey)

			userData, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("userData"))
			require.NoError(t, err)
			require.Equal(t, expectedUserData, userData)

			nonce, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("nonce"))
			require.NoError(t, err)
			require.Equal(t, expectedUserNonce, nonce)

			w.Write(sampleAttestationDocFull)
		}))
	defer server.Close()

	address = server.URL

	// Test with no parameters
	_, err := GetAttestationReport(nil, nil, nil)
	require.NoError(t, err)

	der, _ := pem.Decode(sampleAttestationDocFullPubkey)
	require.NotNil(t, der)
	expectedPublicKey = der.Bytes

	// Test with public key only
	_, err = GetAttestationReport(expectedPublicKey, nil, nil)
	require.NoError(t, err)

	expectedUserData = []byte(sampleAttestationUserData)

	// Test with public key and userData only
	_, err = GetAttestationReport(expectedPublicKey, expectedUserData, nil)
	require.NoError(t, err)

	expectedUserNonce = []byte(sampleAttestationUserNonce)

	// Full test with all parameters
	docReader, err := GetAttestationReport(expectedPublicKey, expectedUserData, expectedUserNonce)
	require.NoError(t, err)

	report, err := verifier.NewSignedAttestationReport(docReader)
	require.NoError(t, err)
	require.NotNil(t, report)

	pcrs := verifier.ConvertPCRsToHex(report.Document.PCRs)
	require.NotEmpty(t, pcrs)

	require.Equal(t, expectedPublicKey, report.Document.UserPublicKey)
	require.Equal(t, sampleAttestationUserData, report.Document.UserData)
	require.Equal(t, sampleAttestationUserNonce, report.Document.UserNonce)
}

func TestGetAttestationReportErrors(t *testing.T) {
	for _, test := range []struct {
		name           string
		responseStatus int
		responseBody   []byte
		expectedError  string
	}{{
		name:           "WellFormedError",
		responseStatus: http.StatusUnauthorized,
		responseBody:   []byte(`{"error": "test error"}`),
		expectedError:  "test error",
	}, {
		name:           "EmptyResponse",
		responseStatus: http.StatusRequestTimeout,
		responseBody:   nil,
		expectedError:  http.StatusText(http.StatusRequestTimeout),
	}, {
		name:           "ResponseWithoutErrorField",
		responseStatus: http.StatusBadRequest,
		responseBody:   []byte(`{"message": "not an error"}`),
		expectedError:  http.StatusText(http.StatusBadRequest),
	}} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(test.responseStatus)
					w.Header().Set("Content-Type", "application/json")
					_, err := w.Write(test.responseBody)
					require.NoError(t, err)
				}),
			)
			defer server.Close()

			address = server.URL

			docReader, err := GetAttestationReport(nil, nil, nil)
			assert.ErrorContains(t, err, test.expectedError)
			assert.Nil(t, docReader)
		})
	}
}
