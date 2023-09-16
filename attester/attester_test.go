package attester

import (
	_ "embed"
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
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(testReport)
		}))
	defer server.Close()

	// invalid address
	docReader, err := GetAttestationReport(nil)
	require.Error(t, err)

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

	docReader, _ = GetAttestationReport(nil)
	docbytes, _ := io.ReadAll(docReader)
	fmt.Printf("%x", docbytes)
}
