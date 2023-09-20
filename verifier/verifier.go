package verifier

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/anjuna-security/go-nitro-attestation/attestdoc"
)

// / Type that represents a map of PCR values
type PCRMap map[uint64]string

// / Creates a Signed Attestation Report from a byte stream
func NewSignedAttestationReport(byteStream io.Reader) (*attestdoc.SignedAttestDoc, error) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(byteStream)
	// Produce the document using the bytes received from the stream
	return attestdoc.FromBytes(buf.Bytes())
}

// / Validate that an attestation report is valid with respect to the root of trust and expected PCR values
func Validate(signedDoc *attestdoc.SignedAttestDoc, expectedPCRs PCRMap) error {
	if err := signedDoc.Validate(); err != nil {
		return err
	}
	if expectedPCRs != nil {
		actualPCRs := signedDoc.Document.PCRs
		return ValidatePCRs(expectedPCRs, actualPCRs)
	}
	return nil
}

// / Utility function for checking whether expected match actual PCR values
func ValidatePCRs(expectedPCRs PCRMap, actualPCRs attestdoc.PCRValues) error {
	for index, expectedPCRStr := range expectedPCRs {
		if index >= attestdoc.NumPCRValues {
			return fmt.Errorf("Invalid PCR index %d", index)
		}
		actualPCR := actualPCRs[index]

		expectedPCR, err := hex.DecodeString(expectedPCRStr)
		if err != nil {
			return fmt.Errorf("Invalid PCR value '%s' at index %d", expectedPCRStr, index)
		}

		if !bytes.Equal(expectedPCR, actualPCR) {
			return fmt.Errorf("PCR value %d does not match: expected: %s, actual %s", index, expectedPCR, actualPCR)
		}
	}
	return nil
}

// / Utility function for converting PCR values to a hex string slice
func ConvertPCRsToHex(data attestdoc.PCRValues) []string {
	if data != nil {
		sz := len(data)
		pcrs := make([]string, sz)
		for i := 0; i < sz; i++ {
			pcrs[i] = hex.EncodeToString(data[i])
		}
		return pcrs
	}
	return nil
}
