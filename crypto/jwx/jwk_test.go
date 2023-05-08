package jwx

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/stretchr/testify/assert"
)

func TestJWKToPrivateKeyJWK(t *testing.T) {
	testKID := "test-kid"
	t.Run("Ed25519", func(tt *testing.T) {
		// known private key
		_, privateKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privateKey)

		// to our representation of a jwk
		_, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(testKID, privateKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privKeyJWK)

		assert.Equal(tt, "OKP", privKeyJWK.KTY)
		assert.Equal(tt, "Ed25519", privKeyJWK.CRV)

		// convert back
		gotPrivKey, err := privKeyJWK.ToPrivateKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPrivKey)
		assert.Equal(tt, privateKey, gotPrivKey)
	})

	t.Run("Dilithium 2", func(tt *testing.T) {
		// known private key
		_, privateKey, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode2)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privateKey)

		// to our representation of a jwk
		_, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(testKID, privateKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, privKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, privKeyJWK.ALG)

		// convert back
		gotPrivKey, err := privKeyJWK.ToPrivateKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPrivKey)
		assert.Equal(tt, privateKey, gotPrivKey)
	})

	t.Run("Dilithium 3", func(tt *testing.T) {
		// known private key
		_, privateKey, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode3)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privateKey)

		// to our representation of a jwk
		_, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(testKID, privateKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, privKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, privKeyJWK.ALG)

		// convert back
		gotPrivKey, err := privKeyJWK.ToPrivateKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPrivKey)
		assert.Equal(tt, privateKey, gotPrivKey)
	})

	t.Run("Dilithium 5", func(tt *testing.T) {
		// known private key
		_, privateKey, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode5)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privateKey)

		// to our representation of a jwk
		_, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(testKID, privateKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, privKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, privKeyJWK.ALG)

		// convert back
		gotPrivKey, err := privKeyJWK.ToPrivateKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPrivKey)
		assert.Equal(tt, privateKey, gotPrivKey)
	})
}

func TestJWKToPublicKeyJWK(t *testing.T) {
	testKID := "test-kid"
	t.Run("Ed25519", func(tt *testing.T) {
		// known public key
		publicKey, _, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, publicKey)

		// to our representation of a jwk
		pubKeyJWK, err := PublicKeyToPublicKeyJWK(testKID, publicKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, pubKeyJWK)

		assert.Equal(tt, "OKP", pubKeyJWK.KTY)
		assert.Equal(tt, "Ed25519", pubKeyJWK.CRV)

		// convert back
		gotPubKey, err := pubKeyJWK.ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPubKey)
		assert.Equal(tt, publicKey, gotPubKey)
	})

	t.Run("Dilithium 2", func(tt *testing.T) {
		// known private key
		publicKey, _, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode2)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, publicKey)

		// to our representation of a jwk
		pubKeyJWK, err := PublicKeyToPublicKeyJWK(testKID, publicKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, pubKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, pubKeyJWK.ALG)

		// convert back
		gotPubKey, err := pubKeyJWK.ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPubKey)
		assert.Equal(tt, publicKey, gotPubKey)
	})

	t.Run("Dilithium 3", func(tt *testing.T) {
		// known private key
		publicKey, _, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode3)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, publicKey)

		// to our representation of a jwk
		pubKeyJWK, err := PublicKeyToPublicKeyJWK(testKID, publicKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, pubKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, pubKeyJWK.ALG)

		// convert back
		gotPubKey, err := pubKeyJWK.ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPubKey)
		assert.Equal(tt, publicKey, gotPubKey)
	})

	t.Run("Dilithium 5", func(tt *testing.T) {
		// known private key
		publicKey, _, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode5)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, publicKey)

		// to our representation of a jwk
		pubKeyJWK, err := PublicKeyToPublicKeyJWK(testKID, publicKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, pubKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, pubKeyJWK.ALG)

		// convert back
		gotPubKey, err := pubKeyJWK.ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPubKey)
		assert.Equal(tt, publicKey, gotPubKey)
	})
}

func TestPublicKeyToPublicKeyJWK(t *testing.T) {
	testKID := "key-id"
	t.Run("RSA", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateRSA2048Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(testKID, pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "RSA", jwk.KTY)

		jwk2, err := PublicKeyToPublicKeyJWK(testKID, &pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "RSA", jwk2.KTY)
	})

	t.Run("Ed25519", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(testKID, pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(testKID, &pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "OKP", jwk2.KTY)
		assert.Equal(tt, "Ed25519", jwk2.CRV)
	})

	t.Run("X25519", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateX25519Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(testKID, pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(testKID, &pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "OKP", jwk2.KTY)
		assert.Equal(tt, "Ed25519", jwk2.CRV)
	})

	t.Run("secp256k1", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateSECP256k1Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(testKID, pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "secp256k1", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(testKID, &pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "EC", jwk2.KTY)
		assert.Equal(tt, "secp256k1", jwk2.CRV)
	})

	t.Run("ecdsa P-256", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateP256Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(testKID, pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-256", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(testKID, &pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "EC", jwk2.KTY)
		assert.Equal(tt, "P-256", jwk2.CRV)
	})

	t.Run("ecdsa P-384", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateP384Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(testKID, pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-384", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(testKID, &pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "EC", jwk2.KTY)
		assert.Equal(tt, "P-384", jwk2.CRV)
	})

	t.Run("Dilithium 2", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode2)
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(testKID, pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, jwk.ALG)

		jwk2, err := PublicKeyToPublicKeyJWK(testKID, &pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, jwk2.ALG)
	})

	t.Run("Dilithium 3", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode3)
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(testKID, pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, jwk.ALG)

		jwk2, err := PublicKeyToPublicKeyJWK(testKID, &pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, jwk2.ALG)
	})

	t.Run("Dilithium 5", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode5)
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(testKID, pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, jwk.ALG)

		jwk2, err := PublicKeyToPublicKeyJWK(testKID, &pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, jwk2.ALG)
	})

	t.Run("unsupported", func(tt *testing.T) {
		jwk, err := PublicKeyToPublicKeyJWK(testKID, nil)
		assert.Error(tt, err)
		assert.Empty(tt, jwk)
	})
}

func TestPrivateKeyToPrivateKeyJWK(t *testing.T) {
	testKID := "test-kid"
	t.Run("RSA", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateRSA2048Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "RSA", jwk.KTY)
	})

	t.Run("Ed25519", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)
	})

	t.Run("X25519", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateX25519Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)
	})

	t.Run("secp256k1", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateSECP256k1Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "secp256k1", jwk.CRV)
	})

	t.Run("ecdsa P-256", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateP256Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-256", jwk.CRV)
	})

	t.Run("ecdsa P-384", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateP384Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-384", jwk.CRV)
	})

	t.Run("Dilithium 2", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode2)
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, jwk.ALG)

		_, jwk2, err := PrivateKeyToPrivateKeyJWK(testKID, &privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, jwk2.ALG)
	})

	t.Run("Dilithium 3", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode3)
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, jwk.ALG)

		_, jwk2, err := PrivateKeyToPrivateKeyJWK(testKID, &privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, jwk2.ALG)
	})

	t.Run("Dilithium 5", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateDilithiumKeyPair(dilithium.Mode5)
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, jwk.ALG)

		_, jwk2, err := PrivateKeyToPrivateKeyJWK(testKID, &privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, jwk2.ALG)
	})

	t.Run("unsupported", func(tt *testing.T) {
		_, jwk, err := PrivateKeyToPrivateKeyJWK(testKID, nil)
		assert.Error(tt, err)
		assert.Empty(tt, jwk)
	})
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
