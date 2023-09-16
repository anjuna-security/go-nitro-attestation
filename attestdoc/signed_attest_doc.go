package attestdoc

import (
	"bytes"
	"crypto/sha512"
	"io/ioutil"
	"time"

	"github.com/anjuna-security/go-nitro-attestation/attester/sign1"
)

// Maximum size of user data that can be included in the attestation document
const MAX_USER_DATA_SIZE_BYTES = 1024

// SignedAttestDoc is the signed attestation document issued by NSM
type SignedAttestDoc struct {

	// Unmodified bytes of CBOR-encoded COSE-signed document.
	// Retrieved from NSM
	Raw []byte

	// Attestation document
	Document *AttestDoc

	// Attestation document COSE Sign1 signature
	Signature *sign1.Sign1Message
}

// Overridable Now function (for testing)
var Now = time.Now

// FromBytes unmarshals signed attestation document from COSE-signed CBOR-encoded bytes
func FromBytes(bytes []byte) (*SignedAttestDoc, error) {
	sign1, err := sign1.FromBytes(bytes)
	if err != nil {
		return nil, err
	}

	doc, err := parseAttestDoc(sign1.Payload)
	if err != nil {
		return nil, err
	}

	return &SignedAttestDoc{
		Document:  doc,
		Signature: sign1,
		Raw:       bytes,
	}, nil
}

// FromFile reads signed attestation document from a file
func FromFile(doc string) (*SignedAttestDoc, error) {
	bytes, err := ioutil.ReadFile(doc)
	if err != nil {
		return nil, err
	}

	return FromBytes(bytes)
}

// validateAtTime validates a signed attestation using curTime to determine if
// if certificates have expired
func (d SignedAttestDoc) validateAtTime(curTime time.Time) error {
	if err := d.Document.validateAtTime(curTime); err != nil {
		return err
	}

	if err := d.Signature.Validate(d.Document.Certificate.PublicKey); err != nil {
		return err
	}

	return nil
}

// Validate validates the signed attestation document
func (d SignedAttestDoc) Validate() error {
	return d.validateAtTime(Now())
}

// IsDebugEnclave returns true for debug enclaves (PCR0 is all zeros) and false otherwise
func (d SignedAttestDoc) IsDebugEnclave() bool {
	allZeros := [sha512.Size384]byte{}
	return bytes.Equal(d.Document.PCRs[0], allZeros[:])
}
