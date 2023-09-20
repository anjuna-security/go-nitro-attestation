package attestdoc

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sampleProdAttestDoc              = "testdata/sample_prod_doc.bin"
	sampleProdAttestDocWithPublicKey = "testdata/sample_prod_doc_with_publickey.bin"
)

var (
	// Test public key
	testPublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8HzUT+AI3KvMEP3H6jWW
gA3tX3vCxhZ1mNYdLSEZmm81BKkX5H9iMY7QPUSASmzeu5xY4XaHK62gj0vSNyS3
rqhIpsU7jSHuwphCEhl8WLpRMuuZDs1keeLHsQxLoYODp8x1WrSynAmBDdqYFKZX
ODfrRMDPQrMXy1NlrVrnhLf+2Ks/MBSFpE96ERNvR29E2RXdd7/wEkaeHhOJ+ib+
7D15r4pnOXuQ53aqrQRcJH/K4FAgh0IvmGMptyVu4Tj/UVQ4T+C5rq46RaqjKhCP
t9yiCBsOoLgfjhAhE2tS8T9/Nf+SwAuC0ZKdiwBRoWc3KMXweFblfVlv1zS15ton
tQIDAQAB
-----END PUBLIC KEY-----`)
)

func Test_canParseSampleDoc(t *testing.T) {
	doc, err := FromFile(sampleProdAttestDoc)
	assert.NoError(t, err)
	assert.NotNil(t, doc)
}

func createPublicKey(pemKey []byte) any {
	pkcs1RSAPublicKey, _ := pem.Decode(pemKey)
	publicKey, err := x509.ParsePKIXPublicKey(pkcs1RSAPublicKey.Bytes)
	if err != nil {
		panic(err)
	}
	return publicKey
}

// Test_canParseSampleDocWithPublicKey tests that we can parse an attestation document
// with a public key and that we parse the public key correctly
func Test_canParseSampleDocWithPublicKey(t *testing.T) {
	// The attestation document was generated using that key
	var publicKey = createPublicKey(testPublicKey)
	doc, err := FromFile(sampleProdAttestDocWithPublicKey)
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.True(t, doc.Document.UserPublicKey.Equal(publicKey))
}

func Test_canValidateSampleDoc(t *testing.T) {
	doc, err := FromFile(sampleProdAttestDoc)
	require.NoError(t, err)
	require.NotNil(t, doc)

	// Validates sample doc pretending it's fresh.
	// An NSM attest doc is only valid for three hours
	err = doc.validateAtTime(doc.Document.Timestamp)
	assert.NoError(t, err)
}

func Test_FromBytes_invalidInput(t *testing.T) {
	_, err := FromBytes([]byte{1, 2, 3})
	assert.Error(t, err)
}

func Test_FromFiles_invalidInput(t *testing.T) {
	_, err := FromFile("/path/to/non-existent/file")
	assert.Error(t, err)
}

func Test_SignedAttestDoc_expiredDocument(t *testing.T) {
	doc, err := FromFile(sampleProdAttestDocWithPublicKey)
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.Error(t, doc.validateAtTime(time.Date(2050, time.January, 1, 0, 0, 0, 0, time.UTC)))
}

func Test_IsDebugEnclave(t *testing.T) {
	doc, err := FromFile(sampleProdAttestDoc)
	require.NoError(t, err)
	assert.False(t, doc.IsDebugEnclave())
	doc.Document.PCRs[0] = make([]byte, sha512.Size384)
	assert.True(t, doc.IsDebugEnclave())
}
