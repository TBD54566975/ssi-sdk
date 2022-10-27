package crypto

import (
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestJWKToPrivateKeyJWK(t *testing.T) {
	// known private key
	_, privateKey, err := GenerateEd25519Key()
	assert.NoError(t, err)
	assert.NotEmpty(t, privateKey)

	// convert to JWK
	jwkKey, err := jwk.New(privateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, jwkKey)

	// to our representation of a jwk
	privKeyJWK, err := JWKToPrivateKeyJWK(jwkKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, privKeyJWK)

	assert.Equal(t, "OKP", privKeyJWK.KTY)
	assert.Equal(t, "Ed25519", privKeyJWK.CRV)
}

func TestJWKToPublicKeyJWK(t *testing.T) {
	// known public key
	publicKey, _, err := GenerateEd25519Key()
	assert.NoError(t, err)
	assert.NotEmpty(t, publicKey)

	// convert to JWK
	key, err := jwk.New(publicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)

	// to our representation of a jwk
	pubKeyJWK, err := JWKToPublicKeyJWK(key)
	assert.NoError(t, err)
	assert.NotEmpty(t, pubKeyJWK)

	assert.Equal(t, "OKP", pubKeyJWK.KTY)
	assert.Equal(t, "Ed25519", pubKeyJWK.CRV)
}

func TestPublicKeyToPublicKeyJWK(t *testing.T) {
	t.Run("RSA", func(tt *testing.T) {
		pubKey, _, err := GenerateRSA2048Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "RSA", jwk.KTY)
	})

	t.Run("Ed25519", func(tt *testing.T) {
		pubKey, _, err := GenerateEd25519Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)
	})

	t.Run("X25519", func(tt *testing.T) {
		pubKey, _, err := GenerateX25519Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)
	})

	t.Run("secp256k1", func(tt *testing.T) {
		pubKey, _, err := GenerateSECP256k1Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "secp256k1", jwk.CRV)
	})

	t.Run("ecdsa P-256", func(tt *testing.T) {
		pubKey, _, err := GenerateP256Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-256", jwk.CRV)
	})

	t.Run("ecdsa P-384", func(tt *testing.T) {
		pubKey, _, err := GenerateP384Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-384", jwk.CRV)
	})

	t.Run("unsupported", func(tt *testing.T) {
		jwk, err := PublicKeyToPublicKeyJWK(nil)
		assert.Error(tt, err)
		assert.Empty(tt, jwk)
	})
}

func TestPrivateKeyToPrivateKeyJWK(t *testing.T) {
	t.Run("RSA", func(tt *testing.T) {
		_, privKey, err := GenerateRSA2048Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "RSA", jwk.KTY)
	})

	t.Run("Ed25519", func(tt *testing.T) {
		_, privKey, err := GenerateEd25519Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)
	})

	t.Run("X25519", func(tt *testing.T) {
		_, privKey, err := GenerateX25519Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)
	})

	t.Run("secp256k1", func(tt *testing.T) {
		_, privKey, err := GenerateSECP256k1Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "secp256k1", jwk.CRV)
	})

	t.Run("ecdsa P-256", func(tt *testing.T) {
		_, privKey, err := GenerateP256Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-256", jwk.CRV)
	})

	t.Run("ecdsa P-384", func(tt *testing.T) {
		_, privKey, err := GenerateP384Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-384", jwk.CRV)
	})

	t.Run("unsupported", func(tt *testing.T) {
		_, jwk, err := PrivateKeyToPrivateKeyJWK(nil)
		assert.Error(tt, err)
		assert.Empty(tt, jwk)
	})
}
