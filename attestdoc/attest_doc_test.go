package attestdoc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parsePCRs_emptyMap(t *testing.T) {
	_, err := parsePCRs(make(map[uint64][]byte))
	assert.ErrorContains(t, err, "unexpected number")
}

func Test_parsePCRs_invalidIndex(t *testing.T) {
	pcrs := make(map[uint64][]byte)
	for i := 0; i < NumPCRValues; i++ {
		pcrs[uint64(i)] = []byte{1}
	}
	// Create an invalid key
	delete(pcrs, NumPCRValues-1)
	pcrs[NumPCRValues] = []byte{1}

	_, err := parsePCRs(pcrs)
	assert.ErrorContains(t, err, "unexpected PCR index")
}

func Test_parsePublicKey_invalidKey(t *testing.T) {
	_, err := parsePublicKey([]byte{1, 2, 3})
	assert.ErrorContains(t, err, "x509.ParsePKIXPublicKey")
}
