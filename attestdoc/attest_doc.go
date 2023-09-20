package attestdoc

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

const (
	// NumPCRValues is the number of PCR values in a successfully parsed attestation document
	NumPCRValues = 16
)

// / Type representing raw PCR values
type PCRValues [][]byte

// AttestDoc is the unsigned attestation document issued by NSM
type AttestDoc struct {

	// Unmodified bytes of CBOR-encoded document.
	// Retrieved from NSM
	Raw []byte

	// Issuing NSM identifier
	IssuerID string

	// Document creation time (ms granularity)
	Timestamp time.Time

	// Type of enclave measurement (e.g. SHA-384)
	PCRType string

	// Enclave measurements
	PCRs PCRValues

	// Certificate with which the document is signed
	Certificate *x509.Certificate

	// Certificate validation chain from document;
	// root AWS certificate at [0] followed by intermediate certs in descending order
	CABundle []*x509.Certificate

	// Public key attested by user (if any)
	UserPublicKey *rsa.PublicKey

	// Additional data attested by user (if any)
	UserData []byte

	// Nonce attested by user (if any)
	UserNonce []byte
}

func parseAttestDoc(bytes []byte) (*AttestDoc, error) {
	var doc struct {
		ModuleID       string            `cbor:"module_id"`
		Digest         string            `cbor:"digest"`
		TimestampMs    uint64            `cbor:"timestamp"`
		PCRs           map[uint64][]byte `cbor:"pcrs"`
		Certificate    []byte            `cbor:"certificate"`
		CABundle       []cbor.RawMessage `cbor:"cabundle"`
		PublicKey      []byte            `cbor:"public_key,omit_empty"`
		AdditionalData []byte            `cbor:"user_data,omit_empty"`
		Nonce          []byte            `cbor:"nonce,omit_empty"`
	}
	if err := cbor.Unmarshal(bytes, &doc); err != nil {
		return nil, err
	}

	cert, err := parseCert(doc.Certificate)
	if err != nil {
		return nil, err
	}

	certBundle, err := parseCertBundle(doc.CABundle)
	if err != nil {
		return nil, err
	}

	timestamp, err := parseTimestamp(doc.TimestampMs)
	if err != nil {
		return nil, err
	}

	pcrs, err := parsePCRs(doc.PCRs)
	if err != nil {
		return nil, err
	}

	publicKey, err := parsePublicKey(doc.PublicKey)
	if err != nil {
		return nil, err
	}

	return &AttestDoc{
		Raw:           bytes,
		IssuerID:      doc.ModuleID,
		Timestamp:     timestamp,
		Certificate:   cert,
		CABundle:      certBundle,
		PCRType:       doc.Digest,
		PCRs:          pcrs,
		UserPublicKey: publicKey,
		UserData:      doc.AdditionalData,
		UserNonce:     doc.Nonce,
	}, nil
}

func (d AttestDoc) validateAtTime(curTime time.Time) error {
	// Publicly available AWS root certificate
	// from https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
	pinnedAWSCert := []byte(`
-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`)
	pinnedCertPool := x509.NewCertPool()
	if !pinnedCertPool.AppendCertsFromPEM(pinnedAWSCert) {
		return errors.New("failed to parse pinned cert")
	}

	interimCertPool := x509.NewCertPool()
	for _, cert := range d.CABundle {
		interimCertPool.AddCert(cert)
	}

	if _, err := d.Certificate.Verify(x509.VerifyOptions{
		Roots:         pinnedCertPool,
		Intermediates: interimCertPool,
		CurrentTime:   curTime,
	}); err != nil {
		return err
	}

	return nil
}

func parseCert(certDER []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(certDER)
}

func parseCertBundle(encodedBundle []cbor.RawMessage) ([]*x509.Certificate, error) {
	bundle := make([]*x509.Certificate, len(encodedBundle))
	for i, bytes := range encodedBundle {
		var der []byte
		if err := cbor.Unmarshal(bytes, &der); err != nil {
			return nil, fmt.Errorf("invalid CA bundle certificate #%d: %v", i, err)
		}

		cert, err := parseCert(der)
		if err != nil {
			return nil, fmt.Errorf("invalid CA bundle certificate #%d: %v", i, err)
		}

		bundle[i] = cert
	}

	return bundle, nil
}

func parseTimestamp(timestampMs uint64) (time.Time, error) {
	timestampSecs := int64(timestampMs / 1000)
	timestampNs := int64((timestampMs % 1000) * 1000)
	return time.Unix(timestampSecs, timestampNs), nil
}

func parsePCRs(PCRs map[uint64][]byte) (PCRValues, error) {
	if len(PCRs) != NumPCRValues {
		return nil, fmt.Errorf("unexpected number=%d of PCR values in attestation document", len(PCRs))
	}
	measurements := make(PCRValues, NumPCRValues)
	for key, val := range PCRs {
		if key >= NumPCRValues {
			return nil, fmt.Errorf("unexpected PCR index=%d in attestation document", key)
		}
		measurements[key] = val
	}
	return measurements, nil
}

func parsePublicKey(bytes []byte) (*rsa.PublicKey, error) {
	if bytes == nil {
		// Public key is optional
		return nil, nil
	}

	parsedKey, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}

	publicKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("parsedKey is not a rsa.PublicKey")
	}

	return publicKey, nil
}
