package cryptosuite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJSONWebKey2020SignerVerifier(t *testing.T) {
	kty := OKP
	crv := crvPtr(Ed25519)
	privKey, jwk, err := GenerateJSONWebKey2020(kty, crv)
	assert.NoError(t, err)
	assert.NotEmpty(t, privKey)
	assert.NotEmpty(t, jwk)

	signer, err := NewJSONWebKey2020Signer("test-signer", kty, crv, privKey)
	assert.NoError(t, err)

	testMessage := []byte("hello world")
	signature, err := signer.Sign(testMessage)
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	verifier := NewJSONWebKey2020Verifier(*jwk)
	assert.NotEmpty(t, verifier)

	err = verifier.Verify(testMessage, signature)
	assert.NoError(t, err)
}
