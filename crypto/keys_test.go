package crypto

import (
	"testing"

	"github.com/cloudflare/circl/sign/dilithium"
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

			kt, err := GetKeyTypeFromPrivateKey(priv)
			assert.NoError(tt, err)
			assert.Equal(tt, keyType, kt)
		})
	}

	for _, keyType := range GetExperimentalKeyTypes() {
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

			kt, err := GetKeyTypeFromPrivateKey(priv)
			assert.NoError(tt, err)
			assert.Equal(tt, keyType, kt)
		})
	}

	for _, keyType := range GetSupportedKeyTypes() {
		t.Run(string(keyType)+" with pointers", func(tt *testing.T) {
			pub, priv, err := GenerateKeyByKeyType(keyType)

			assert.NoError(tt, err)
			assert.NotEmpty(tt, pub)
			assert.NotEmpty(tt, priv)

			pubKeyBytes, err := PubKeyToBytes(&pub)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKeyBytes)

			reconstructedPub, err := BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, reconstructedPub)
			assert.EqualValues(tt, pub, reconstructedPub)

			privKeyBytes, err := PrivKeyToBytes(&priv)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, privKeyBytes)

			reconstructedPriv, err := BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, reconstructedPriv)
			assert.EqualValues(tt, priv, reconstructedPriv)

			kt, err := GetKeyTypeFromPrivateKey(&priv)
			assert.NoError(tt, err)
			assert.Equal(tt, keyType, kt)
		})
	}

	for _, keyType := range GetExperimentalKeyTypes() {
		t.Run(string(keyType)+" with pointers", func(tt *testing.T) {
			pub, priv, err := GenerateKeyByKeyType(keyType)

			assert.NoError(tt, err)
			assert.NotEmpty(tt, pub)
			assert.NotEmpty(tt, priv)

			pubKeyBytes, err := PubKeyToBytes(&pub)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, pubKeyBytes)

			reconstructedPub, err := BytesToPubKey(pubKeyBytes, keyType)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, reconstructedPub)
			assert.EqualValues(tt, pub, reconstructedPub)

			privKeyBytes, err := PrivKeyToBytes(&priv)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, privKeyBytes)

			reconstructedPriv, err := BytesToPrivKey(privKeyBytes, keyType)
			assert.NoError(tt, err)
			assert.NotEmpty(tt, reconstructedPriv)
			assert.EqualValues(tt, priv, reconstructedPriv)

			kt, err := GetKeyTypeFromPrivateKey(&priv)
			assert.NoError(tt, err)
			assert.Equal(tt, keyType, kt)
		})
	}
}

func TestDilithiumKeys(t *testing.T) {
	t.Run("Able to generate dilithium key pairs for each mode", func(tt *testing.T) {
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
			tt.Run(test.name, func(ttt *testing.T) {
				pk, sk, err := GenerateDilithiumKeyPair(test.m)
				assert.NoError(ttt, err)
				assert.NotEmpty(ttt, pk)
				assert.NotEmpty(ttt, sk)
			})
		}
	})

	t.Run("Able to extract the mode for each Dilithium private key type", func(tt *testing.T) {
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
			tt.Run(test.m.Name(), func(ttt *testing.T) {
				_, privKey, err := GenerateDilithiumKeyPair(test.m)
				assert.NoError(tt, err)

				mode, err := GetModeFromDilithiumPrivateKey(privKey)
				assert.NoError(tt, err)
				assert.Equal(tt, test.m, mode)
			})
		}
	})

	t.Run("Able to extract the mode for each Dilithium public key type", func(tt *testing.T) {
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
			tt.Run(test.m.Name(), func(ttt *testing.T) {
				pubKey, _, err := GenerateDilithiumKeyPair(test.m)
				assert.NoError(tt, err)

				mode, err := GetModeFromDilithiumPublicKey(pubKey)
				assert.NoError(tt, err)
				assert.Equal(tt, test.m, mode)
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
