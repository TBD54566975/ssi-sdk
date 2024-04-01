package crypto

import (
	"testing"

	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/stretchr/testify/assert"
)

func TestKeyToBytes(t *testing.T) {
	for _, keyType := range GetSupportedKeyTypes() {
		t.Run(string(keyType), func(t *testing.T) {
			pub, priv, err := GenerateKeyByKeyType(keyType)

			assert.NoError(t, err)
			assert.NotEmpty(t, pub)
			assert.NotEmpty(t, priv)

			pubKeyBytes, err := PubKeyToBytes(pub)
			assert.NoError(t, err)
			assert.NotEmpty(t, pubKeyBytes)

			reconstructedPub, err := BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPub)
			assert.EqualValues(t, pub, reconstructedPub)

			privKeyBytes, err := PrivKeyToBytes(priv)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKeyBytes)

			reconstructedPriv, err := BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPriv)
			assert.EqualValues(t, priv, reconstructedPriv)

			kt, err := GetKeyTypeFromPrivateKey(priv)
			assert.NoError(t, err)
			assert.Equal(t, keyType, kt)
		})
	}

	for _, keyType := range GetExperimentalKeyTypes() {
		t.Run(string(keyType), func(t *testing.T) {
			pub, priv, err := GenerateKeyByKeyType(keyType)

			assert.NoError(t, err)
			assert.NotEmpty(t, pub)
			assert.NotEmpty(t, priv)

			pubKeyBytes, err := PubKeyToBytes(pub)
			assert.NoError(t, err)
			assert.NotEmpty(t, pubKeyBytes)

			reconstructedPub, err := BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPub)
			assert.EqualValues(t, pub, reconstructedPub)

			privKeyBytes, err := PrivKeyToBytes(priv)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKeyBytes)

			reconstructedPriv, err := BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPriv)
			assert.EqualValues(t, priv, reconstructedPriv)

			kt, err := GetKeyTypeFromPrivateKey(priv)
			assert.NoError(t, err)
			assert.Equal(t, keyType, kt)
		})
	}

	for _, keyType := range GetSupportedKeyTypes() {
		t.Run(string(keyType)+" with pointers", func(t *testing.T) {
			pub, priv, err := GenerateKeyByKeyType(keyType)

			assert.NoError(t, err)
			assert.NotEmpty(t, pub)
			assert.NotEmpty(t, priv)

			pubKeyBytes, err := PubKeyToBytes(&pub)
			assert.NoError(t, err)
			assert.NotEmpty(t, pubKeyBytes)

			reconstructedPub, err := BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPub)
			assert.EqualValues(t, pub, reconstructedPub)

			privKeyBytes, err := PrivKeyToBytes(&priv)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKeyBytes)

			reconstructedPriv, err := BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPriv)
			assert.EqualValues(t, priv, reconstructedPriv)

			kt, err := GetKeyTypeFromPrivateKey(&priv)
			assert.NoError(t, err)
			assert.Equal(t, keyType, kt)
		})
	}

	for _, keyType := range GetExperimentalKeyTypes() {
		t.Run(string(keyType)+" with pointers", func(t *testing.T) {
			pub, priv, err := GenerateKeyByKeyType(keyType)

			assert.NoError(t, err)
			assert.NotEmpty(t, pub)
			assert.NotEmpty(t, priv)

			pubKeyBytes, err := PubKeyToBytes(&pub)
			assert.NoError(t, err)
			assert.NotEmpty(t, pubKeyBytes)

			reconstructedPub, err := BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPub)
			assert.EqualValues(t, pub, reconstructedPub)

			privKeyBytes, err := PrivKeyToBytes(&priv)
			assert.NoError(t, err)
			assert.NotEmpty(t, privKeyBytes)

			reconstructedPriv, err := BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(t, err)
			assert.NotEmpty(t, reconstructedPriv)
			assert.EqualValues(t, priv, reconstructedPriv)

			kt, err := GetKeyTypeFromPrivateKey(&priv)
			assert.NoError(t, err)
			assert.Equal(t, keyType, kt)
		})
	}
}

func TestDilithiumKeys(t *testing.T) {
	t.Run("Able to generate dilithium key pairs for each mode", func(t *testing.T) {
		tests := []struct {
			name string
			m    dilithium.Mode
		}{
			{
				"mode2",
				dilithium.Mode2,
			},
			{
				"mode3",
				dilithium.Mode3,
			},
			{
				"mode5",
				dilithium.Mode5,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				pk, sk, err := GenerateDilithiumKeyPair(test.m)
				assert.NoError(t, err)
				assert.NotEmpty(t, pk)
				assert.NotEmpty(t, sk)
			})
		}
	})

	t.Run("Able to extract the mode for each Dilithium private key type", func(t *testing.T) {
		tests := []struct {
			m dilithium.Mode
		}{
			{
				dilithium.Mode2,
			},
			{
				dilithium.Mode3,
			},
			{
				dilithium.Mode5,
			},
		}
		for _, test := range tests {
			t.Run(test.m.Name(), func(t *testing.T) {
				_, privKey, err := GenerateDilithiumKeyPair(test.m)
				assert.NoError(t, err)

				mode, err := GetModeFromDilithiumPrivateKey(privKey)
				assert.NoError(t, err)
				assert.Equal(t, test.m, mode)
			})
		}
	})

	t.Run("Able to extract the mode for each Dilithium public key type", func(t *testing.T) {
		tests := []struct {
			m dilithium.Mode
		}{
			{
				dilithium.Mode2,
			},
			{
				dilithium.Mode3,
			},
			{
				dilithium.Mode5,
			},
		}
		for _, test := range tests {
			t.Run(test.m.Name(), func(t *testing.T) {
				pubKey, _, err := GenerateDilithiumKeyPair(test.m)
				assert.NoError(t, err)

				mode, err := GetModeFromDilithiumPublicKey(pubKey)
				assert.NoError(t, err)
				assert.Equal(t, test.m, mode)
			})
		}
	})
}

func TestSECP256k1Conversions(t *testing.T) {
	pk, sk, err := GenerateSECP256k1Key()
	assert.NoError(t, err)

	ecdsaPK := pk.ToECDSA()
	ecdsaSK := sk.ToECDSA()

	gotPK := SECP256k1ECDSAPubKeyToSECP256k1(*ecdsaPK)
	gotSK := SECP256k1ECDSASPrivKeyToSECP256k1(*ecdsaSK)

	assert.Equal(t, pk, gotPK)
	assert.Equal(t, sk, gotSK)
}
