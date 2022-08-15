package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyToBytes(t *testing.T) {
	for _, keyType := range GetSupportedKeyTypes() {
		t.Run(string(keyType), func(tt *testing.T) {
			pub, priv, err := GenerateKeyByKeyType(keyType)

			assert.NoError(tt, err)
			assert.NotEmpty(tt, pub)
			assert.NotEmpty(tt, priv)

			pubKeyBytes, err := PubKeyToBytes(pub)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKeyBytes)

			reconstructedPub, err := BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, reconstructedPub)
			assert.EqualValues(tt, pub, reconstructedPub)

			privKeyBytes, err := PrivKeyToBytes(priv)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, privKeyBytes)

			reconstructedPriv, err := BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, reconstructedPriv)
			assert.EqualValues(tt, priv, reconstructedPriv)
		})
	}
}
