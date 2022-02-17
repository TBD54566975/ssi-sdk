package cryptosuite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestProvable struct {
	Message string `json:"message,omitempty"`
	Proof   *Proof `json:"proof,omitempty"`
}

func (t *TestProvable) GetProof() *Proof {
	return t.Proof
}

func (t *TestProvable) SetProof(p *Proof) {
	t.Proof = p
}

func TestJSONWebSignature2020Suite(t *testing.T) {
	pk, jwk, err := GenerateEd25519JSONWebKey2020()
	assert.NoError(t, err)
	assert.NotEmpty(t, pk)
	assert.NotEmpty(t, jwk)

	tp := TestProvable{
		Message: "test",
	}

	signed, err := SignProvable(pk, &tp)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)
}
