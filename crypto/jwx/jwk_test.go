package jwx

import (
	"crypto/ecdsa"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
)

func TestKeyToJWK(t *testing.T) {
	testKID := "test-kid"

	for _, keyType := range crypto.GetSupportedJWKKeyTypes() {
		t.Run(string(keyType), func(tt *testing.T) {
			pub, priv, err := crypto.GenerateKeyByKeyType(keyType)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pub)
			assert.NotEmpty(tt, priv)

			pubKeyJWK, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(testKID, priv)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKeyJWK)
			assert.NotEmpty(tt, privKeyJWK)

			otherPubKeyJWK, err := PublicKeyToPublicKeyJWK(testKID, pub)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, otherPubKeyJWK)
			assert.Equal(tt, pubKeyJWK, otherPubKeyJWK)

			privKey, err := privKeyJWK.ToPrivateKey()
			assert.NoError(tt, err)
			assert.NotEmpty(tt, privKey)

			pubKey, err := pubKeyJWK.ToPublicKey()
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKey)

			if keyType == crypto.SECP256k1 {
				pubKey = crypto.SECP256k1ECDSAPubKeyToSECP256k1(pubKey.(ecdsa.PublicKey))
				privKey = crypto.SECP256k1ECDSASPrivKeyToSECP256k1(privKey.(ecdsa.PrivateKey))
			}

			assert.Equal(tt, priv, privKey)
			assert.Equal(tt, pub, pubKey)
		})
	}

	for _, keyType := range crypto.GetExperimentalKeyTypes() {
		t.Run(string(keyType), func(tt *testing.T) {
			pub, priv, err := crypto.GenerateKeyByKeyType(keyType)

			assert.NoError(tt, err)
			assert.NotEmpty(tt, pub)
			assert.NotEmpty(tt, priv)

			pubKeyJWK, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(testKID, priv)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKeyJWK)
			assert.NotEmpty(tt, privKeyJWK)

			otherPubKeyJWK, err := PublicKeyToPublicKeyJWK(testKID, pub)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, otherPubKeyJWK)
			assert.Equal(tt, pubKeyJWK, otherPubKeyJWK)

			privKey, err := privKeyJWK.ToPrivateKey()
			assert.NoError(tt, err)
			assert.NotEmpty(tt, privKey)
			assert.EqualValues(tt, priv, privKey)

			pubKey, err := pubKeyJWK.ToPublicKey()
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKey)
			assert.EqualValues(tt, pub, pubKey)
		})
	}
}

// https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-00.html#section-6.1.1
func TestDilithiumVectors(t *testing.T) {
	t.Run("Dilithium Private Key", func(tt *testing.T) {
		var pubKeyJWK PublicKeyJWK
		retrieveTestVectorAs(tt, dilithiumPublicJWK, &pubKeyJWK)
		assert.NotEmpty(tt, pubKeyJWK)
		assert.Equal(tt, DilithiumKTY, pubKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, pubKeyJWK.ALG)

		gotPubKey, err := pubKeyJWK.ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPubKey)
	})

	t.Run("Dilithium Private Key", func(tt *testing.T) {
		var privKeyJWK PrivateKeyJWK
		retrieveTestVectorAs(tt, dilithiumPrivateJWK, &privKeyJWK)
		assert.NotEmpty(tt, privKeyJWK)
		assert.Equal(tt, DilithiumKTY, privKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, privKeyJWK.ALG)

		gotPrivKey, err := privKeyJWK.ToPrivateKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPrivKey)
	})
}
