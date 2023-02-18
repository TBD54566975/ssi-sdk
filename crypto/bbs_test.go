package crypto

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateBBSKeyPair(t *testing.T) {
	t.Run("generate key pair", func(tt *testing.T) {
		pubKey, privKey, err := GenerateBBSKeyPair()
		assert.NotNil(tt, pubKey)
		assert.NotNil(tt, privKey)
		assert.NoError(tt, err)
	})

	t.Run("sign and verify message", func(tt *testing.T) {
		pubKey, privKey, err := GenerateBBSKeyPair()
		assert.NoError(tt, err)

		msg := []byte("hello world")
		signature, err := SignBBSMessage(privKey, msg)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signature)

		err = VerifyBBSMessage(pubKey, signature, msg)
		assert.NoError(tt, err)
	})
}

func TestBBSSignatureEncoding(t *testing.T) {
	pubKey, privKey, err := GenerateBBSKeyPair()
	assert.NotNil(t, pubKey)
	assert.NotNil(t, privKey)
	assert.NoError(t, err)

	signature, err := SignBBSMessage(privKey, []byte("hello world"))
	assert.NoError(t, err)
	assert.NotEmpty(t, signature)

	encoded := base64.RawStdEncoding.EncodeToString(signature)
	assert.NotEmpty(t, encoded)

	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	assert.NoError(t, err)
	assert.NotEmpty(t, decoded)

	assert.Equal(t, signature, decoded)

	err = VerifyBBSMessage(pubKey, decoded, []byte("hello world"))
	assert.NoError(t, err)
}
