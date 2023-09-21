package attester

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
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
	expectedData = []byte("test")
	docReader, _ = GetAttestationReport(expectedData)
	docbytes, _ := io.ReadAll(docReader)
	fmt.Printf("%x", docbytes)
}
