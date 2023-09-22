package attester

import (
	_ "embed"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/anjuna-security/go-nitro-attestation/verifier"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/sample_prod_doc.bin
var testReport []byte

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
	docReader, err := GetAttestationReport(nil)
	require.Error(t, err)
	require.Nil(t, docReader)

	// valid address
	address = server.URL

	docReader, err = GetAttestationReport(nil)
	require.NoError(t, err)
	require.NotNil(t, docReader)

	doc, err := verifier.NewSignedAttestationReport(docReader)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.NotEmpty(t, doc.Document.PCRs)
	require.NotEmpty(t, doc.Document.PCRs[0])

	// valid user data encoding
	expectedData, _ = base64.StdEncoding.DecodeString("SGVsbG8gV29ybGQhCg==")
	docReader, err = GetAttestationReport(expectedData)
	require.NoError(t, err)

	report, err := verifier.NewSignedAttestationReport(docReader)
	require.NoError(t, err)
	require.NotNil(t, report)

	pcrs := verifier.ConvertPCRsToHex(report.Document.PCRs)
	require.NotEmpty(t, pcrs)

	require.Equal(t, expectedData, report.Document.UserData)
}
