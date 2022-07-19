package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyToBytes(t *testing.T) {
	t.Run("ed25519", func(tt *testing.T) {
		pub, priv, err := GenerateKeyByKeyType(Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pub)
		assert.NotEmpty(tt, priv)

		pubKeyBytes, err := PubKeyToBytes(pub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKeyBytes)

		reconstructedPub, err := BytesToPubKey(pubKeyBytes, Ed25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reconstructedPub)
		assert.EqualValues(tt, pub, reconstructedPub)

		privKeyBytes, err := PrivKeyToBytes(priv)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKeyBytes)
	})

	t.Run("X25519", func(tt *testing.T) {
		pub, priv, err := GenerateKeyByKeyType(X25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pub)
		assert.NotEmpty(tt, priv)

		pubKeyBytes, err := PubKeyToBytes(pub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKeyBytes)

		reconstructedPub, err := BytesToPubKey(pubKeyBytes, X25519)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reconstructedPub)
		assert.EqualValues(tt, pub, reconstructedPub)

		privKeyBytes, err := PrivKeyToBytes(priv)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKeyBytes)
	})

	t.Run("Secp256k1", func(tt *testing.T) {
		pub, priv, err := GenerateKeyByKeyType(Secp256k1)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pub)
		assert.NotEmpty(tt, priv)

		pubKeyBytes, err := PubKeyToBytes(pub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKeyBytes)

		reconstructedPub, err := BytesToPubKey(pubKeyBytes, Secp256k1)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reconstructedPub)
		assert.EqualValues(tt, pub, reconstructedPub)

		privKeyBytes, err := PrivKeyToBytes(priv)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKeyBytes)
	})

	t.Run("P224", func(tt *testing.T) {
		pub, priv, err := GenerateKeyByKeyType(P224)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pub)
		assert.NotEmpty(tt, priv)

		pubKeyBytes, err := PubKeyToBytes(pub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKeyBytes)

		reconstructedPub, err := BytesToPubKey(pubKeyBytes, P224)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reconstructedPub)
		assert.EqualValues(tt, pub, reconstructedPub)

		privKeyBytes, err := PrivKeyToBytes(priv)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKeyBytes)
	})

	t.Run("P256", func(tt *testing.T) {
		pub, priv, err := GenerateKeyByKeyType(P256)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pub)
		assert.NotEmpty(tt, priv)

		pubKeyBytes, err := PubKeyToBytes(pub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKeyBytes)

		reconstructedPub, err := BytesToPubKey(pubKeyBytes, P256)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reconstructedPub)
		assert.EqualValues(tt, pub, reconstructedPub)

		privKeyBytes, err := PrivKeyToBytes(priv)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKeyBytes)
	})

	t.Run("P384", func(tt *testing.T) {
		pub, priv, err := GenerateKeyByKeyType(P384)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pub)
		assert.NotEmpty(tt, priv)

		pubKeyBytes, err := PubKeyToBytes(pub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKeyBytes)

		reconstructedPub, err := BytesToPubKey(pubKeyBytes, P384)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reconstructedPub)
		assert.EqualValues(tt, pub, reconstructedPub)

		privKeyBytes, err := PrivKeyToBytes(priv)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKeyBytes)
	})

	t.Run("P521", func(tt *testing.T) {
		pub, priv, err := GenerateKeyByKeyType(P521)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pub)
		assert.NotEmpty(tt, priv)

		pubKeyBytes, err := PubKeyToBytes(pub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKeyBytes)

		reconstructedPub, err := BytesToPubKey(pubKeyBytes, P521)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reconstructedPub)
		assert.EqualValues(tt, pub, reconstructedPub)

		privKeyBytes, err := PrivKeyToBytes(priv)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKeyBytes)
	})

	t.Run("RSA", func(tt *testing.T) {
		pub, priv, err := GenerateKeyByKeyType(RSA)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pub)
		assert.NotEmpty(tt, priv)

		pubKeyBytes, err := PubKeyToBytes(pub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKeyBytes)
		
		reconstructedPub, err := BytesToPubKey(pubKeyBytes, RSA)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, reconstructedPub)
		assert.EqualValues(tt, pub, reconstructedPub)

		privKeyBytes, err := PrivKeyToBytes(priv)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKeyBytes)
	})
}
