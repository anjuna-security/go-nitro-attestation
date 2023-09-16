package verifier

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"io"
	"os"
	"testing"
	"time"

	"github.com/anjuna-security/go-nitro-attestation/attestdoc"
	"github.com/stretchr/testify/assert"
)

const (
	sampleProdAttestDoc = "../attestdoc/testdata/sample_prod_doc.bin"
)

var (
	certificateDate = time.Date(2021, 3, 17, 23, 0, 0, 0, time.UTC)
)

func sampleAttestDoc() io.Reader {
	docFile, err := os.Open(sampleProdAttestDoc)
	if err != nil {
		panic(err)
	}
	return bufio.NewReader(docFile)
}

func generateRandomPCR() []byte {
	pcr := make([]byte, sha512.Size384)
	_, err := rand.Read(pcr)
	if err != nil {
		panic(err)
	}
	return pcr
}

func generateRandomPCRs() attestdoc.PCRValues {
	pcrs := make(attestdoc.PCRValues, attestdoc.NumPCRValues)
	for i := 0; i < len(pcrs); i++ {
		pcrs[i] = generateRandomPCR()
	}
	return pcrs
}

func Test_NewSignedAttestationReport_invalid(t *testing.T) {
	stream := bytes.NewReader([]byte{1, 2, 3})
	_, err := NewSignedAttestationReport(stream)
	assert.Error(t, err)
}

func Test_NewSignedAttestationReport_empty(t *testing.T) {
	stream := bytes.NewReader([]byte{})
	_, err := NewSignedAttestationReport(stream)
	assert.Error(t, err)
}

func Test_NewSignedAttestationReport(t *testing.T) {
	doc, err := NewSignedAttestationReport(sampleAttestDoc())
	assert.NoError(t, err)
	assert.NotNil(t, doc.Document)
}

func Test_ValidatePCRs_mismatch(t *testing.T) {
	actualPCRs := generateRandomPCRs()
	expectedPCRs := PCRMap{
		1: generateRandomPCR(),
	}
	err := ValidatePCRs(expectedPCRs, actualPCRs)
	assert.ErrorContains(t, err, "does not match")
}

func Test_ValidatePCRs_partialMatch(t *testing.T) {
	actualPCRs := generateRandomPCRs()
	expectedPCRs := PCRMap{
		0: actualPCRs[0],
		8: generateRandomPCR(),
	}
	err := ValidatePCRs(expectedPCRs, actualPCRs)
	assert.ErrorContains(t, err, "does not match")
}

func Test_ValidatePCRs(t *testing.T) {
	actualPCRs := generateRandomPCRs()
	expectedPCRs := PCRMap{
		0: actualPCRs[0],
		8: actualPCRs[8],
	}
	err := ValidatePCRs(expectedPCRs, actualPCRs)
	assert.NoError(t, err)
}

func Test_Validate_noExpectedPCRs(t *testing.T) {
	attestdoc.Now = func() time.Time { return certificateDate }
	defer func() { attestdoc.Now = time.Now }()

	doc, err := NewSignedAttestationReport(sampleAttestDoc())
	assert.NoError(t, err)
	err = Validate(doc, nil)
	assert.NoError(t, err)
}

func Test_Validate_mismatch(t *testing.T) {
	attestdoc.Now = func() time.Time { return certificateDate }
	defer func() { attestdoc.Now = time.Now }()

	doc, err := NewSignedAttestationReport(sampleAttestDoc())
	assert.NoError(t, err)
	actualPCRs := doc.Document.PCRs
	expectedPCRs := PCRMap{
		0: generateRandomPCR(),
		8: actualPCRs[8],
	}
	err = Validate(doc, expectedPCRs)
	assert.ErrorContains(t, err, "does not match")
}

func Test_Validate_invalidIndex(t *testing.T) {
	attestdoc.Now = func() time.Time { return certificateDate }
	defer func() { attestdoc.Now = time.Now }()

	doc, err := NewSignedAttestationReport(sampleAttestDoc())
	assert.NoError(t, err)
	expectedPCRs := PCRMap{
		16: generateRandomPCR(),
	}
	err = Validate(doc, expectedPCRs)
	assert.ErrorContains(t, err, "Invalid PCR index")
}

func Test_Validate(t *testing.T) {
	attestdoc.Now = func() time.Time { return certificateDate }
	defer func() { attestdoc.Now = time.Now }()

	doc, err := NewSignedAttestationReport(sampleAttestDoc())
	assert.NoError(t, err)
	actualPCRs := doc.Document.PCRs
	expectedPCRs := PCRMap{
		0: actualPCRs[0],
		8: actualPCRs[8],
	}
	err = Validate(doc, expectedPCRs)
	assert.NoError(t, err)
}

func Test_ConvertPCRsToHex_nil(t *testing.T) {
	hexPCRs := ConvertPCRsToHex(nil)
	assert.Nil(t, hexPCRs)
}

func Test_ConvertPCRsToHex_empty(t *testing.T) {
	hexPCRs := ConvertPCRsToHex(attestdoc.PCRValues{})
	assert.Equal(t, 0, len(hexPCRs))
}

func Test_ConvertPCRsToHex(t *testing.T) {
	pcrs := generateRandomPCRs()
	hexPCRs := ConvertPCRsToHex(pcrs)
	assert.Equal(t, attestdoc.NumPCRValues, len(pcrs))
	assert.Equal(t, len(pcrs), len(hexPCRs))
	for i := 0; i < len(pcrs); i++ {
		assert.Equal(t, hex.EncodeToString(pcrs[i]), hexPCRs[i])
	}
}
