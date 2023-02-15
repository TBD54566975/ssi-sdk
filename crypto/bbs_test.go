package crypto

import (
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
