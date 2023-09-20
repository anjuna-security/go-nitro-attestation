package sign1

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// Represents a decoded COSE_Sign1 struct.
// Contains the payload, signature and a header (signed)
type Sign1Message struct {
	Payload   []byte
	Signature []byte
	Header    []byte
}

// Unmarshals COSE_Sign1 message from CBOR bytes.
// Currently only supports untagged CBOR structs
func FromBytes(bytes []byte) (*Sign1Message, error) {
	var msg struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected map[interface{}]interface{}
		Payload     []byte
		Signature   []byte
	}
	if err := cbor.Unmarshal(bytes, &msg); err != nil {
		return nil, err
	}

	return &Sign1Message{
		Payload:   msg.Payload,
		Signature: msg.Signature,
		Header:    msg.Protected,
	}, nil
}

// Validates COSE_Sign1 signature given a public key.
// Currently only supports ECDSA signatures w/ SHA-384
func (m *Sign1Message) Validate(key interface{}) error {
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("unexpected key type: %T", key)
	}

	hash, err := m.hash()
	if err != nil {
		return err
	}

	r, s := m.getSigComponents()
	if !ecdsa.Verify(ecdsaKey, hash, r, s) {
		return errors.New("invalid signature")
	}

	return nil
}

func (m *Sign1Message) hash() ([]byte, error) {
	// Payload is combined with additional data into a SigStruct (RFC #8152);
	// CBOR-encoded SigStruct forms a canonical byte stream that is hashed (and signed)
	type SigStruct struct {
		_             struct{} `cbor:",toarray"`
		Context       string
		BodyProtected []byte
		ExternalAAD   []byte
		Payload       []byte
	}
	msg, err := cbor.Marshal(&SigStruct{
		Context:       "Signature1",
		BodyProtected: m.Header,
		ExternalAAD:   []byte{},
		Payload:       m.Payload,
	})
	if err != nil {
		return nil, err
	}

	hasher := crypto.SHA384.New()
	if _, err = hasher.Write(msg); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func (m *Sign1Message) getSigComponents() (*big.Int, *big.Int) {
	sigSize := len(m.Signature)
	r := big.NewInt(0).SetBytes(m.Signature[:sigSize/2])
	s := big.NewInt(0).SetBytes(m.Signature[sigSize/2:])

	return r, s
}
