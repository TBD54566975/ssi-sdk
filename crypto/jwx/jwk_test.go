package jwx

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

func TestJWKToPrivateKeyJWK(t *testing.T) {
	t.Run("Ed25519", func(tt *testing.T) {
		// known private key
		_, privateKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privateKey)

		// convert to JWK
		key, err := jwk.FromRaw(privateKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, key)

		// to our representation of a jwk
		privKeyJWK, err := JWKToPrivateKeyJWK(key)
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
		_, privateKey, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium2)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privateKey)

		// to our representation of a jwk
		_, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(privateKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, privKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, privKeyJWK.Alg)

		// convert back
		gotPrivKey, err := privKeyJWK.ToPrivateKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPrivKey)
		assert.Equal(tt, privateKey, gotPrivKey)
	})

	t.Run("Dilithium 3", func(tt *testing.T) {
		// known private key
		_, privateKey, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium3)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privateKey)

		// to our representation of a jwk
		_, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(privateKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, privKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, privKeyJWK.Alg)

		// convert back
		gotPrivKey, err := privKeyJWK.ToPrivateKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPrivKey)
		assert.Equal(tt, privateKey, gotPrivKey)
	})

	t.Run("Dilithium 5", func(tt *testing.T) {
		// known private key
		_, privateKey, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium5)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, privateKey)

		// to our representation of a jwk
		_, privKeyJWK, err := PrivateKeyToPrivateKeyJWK(privateKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, privKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, privKeyJWK.Alg)

		// convert back
		gotPrivKey, err := privKeyJWK.ToPrivateKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPrivKey)
		assert.Equal(tt, privateKey, gotPrivKey)
	})
}

func TestJWKToPublicKeyJWK(t *testing.T) {
	t.Run("Ed25519", func(tt *testing.T) {
		// known public key
		publicKey, _, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, publicKey)

		// convert to JWK
		key, err := jwk.FromRaw(publicKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, key)

		// to our representation of a jwk
		pubKeyJWK, err := JWKToPublicKeyJWK(key)
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
		publicKey, _, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium2)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, publicKey)

		// to our representation of a jwk
		pubKeyJWK, err := PublicKeyToPublicKeyJWK(publicKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, pubKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, pubKeyJWK.Alg)

		// convert back
		gotPubKey, err := pubKeyJWK.ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPubKey)
		assert.Equal(tt, publicKey, gotPubKey)
	})

	t.Run("Dilithium 3", func(tt *testing.T) {
		// known private key
		publicKey, _, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium3)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, publicKey)

		// to our representation of a jwk
		pubKeyJWK, err := PublicKeyToPublicKeyJWK(publicKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, pubKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, pubKeyJWK.Alg)

		// convert back
		gotPubKey, err := pubKeyJWK.ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPubKey)
		assert.Equal(tt, publicKey, gotPubKey)
	})

	t.Run("Dilithium 5", func(tt *testing.T) {
		// known private key
		publicKey, _, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium5)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, publicKey)

		// to our representation of a jwk
		pubKeyJWK, err := PublicKeyToPublicKeyJWK(publicKey)
		assert.NoError(tt, err)

		assert.Equal(tt, DilithiumKTY, pubKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, pubKeyJWK.Alg)

		// convert back
		gotPubKey, err := pubKeyJWK.ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPubKey)
		assert.Equal(tt, publicKey, gotPubKey)
	})
}

func TestJWKFromPrivateKeyJWK(t *testing.T) {
	// known private key
	_, privateKey, err := crypto.GenerateEd25519Key()
	assert.NoError(t, err)
	assert.NotEmpty(t, privateKey)

	// convert to JWK
	key, err := jwk.FromRaw(privateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)

	// to our representation of a jwk
	privKeyJWK, err := JWKToPrivateKeyJWK(key)
	assert.NoError(t, err)
	assert.NotEmpty(t, privKeyJWK)

	assert.Equal(t, "OKP", privKeyJWK.KTY)
	assert.Equal(t, "Ed25519", privKeyJWK.CRV)

	// back to a jwk
	gotJWK, err := JWKFromPrivateKeyJWK(*privKeyJWK)
	assert.NoError(t, err)
	assert.NotEmpty(t, gotJWK)
	assert.Equal(t, key, gotJWK)
}

func TestJWKFromPublicKeyJWK(t *testing.T) {
	// known public key
	publicKey, _, err := crypto.GenerateEd25519Key()
	assert.NoError(t, err)
	assert.NotEmpty(t, publicKey)

	// convert to JWK
	key, err := jwk.FromRaw(publicKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)

	// to our representation of a jwk
	pubKeyJWK, err := JWKToPublicKeyJWK(key)
	assert.NoError(t, err)
	assert.NotEmpty(t, pubKeyJWK)

	assert.Equal(t, "OKP", pubKeyJWK.KTY)
	assert.Equal(t, "Ed25519", pubKeyJWK.CRV)

	// back to a jwk
	gotJWK, err := JWKFromPublicKeyJWK(*pubKeyJWK)
	assert.NoError(t, err)
	assert.NotEmpty(t, gotJWK)
	assert.Equal(t, key, gotJWK)
}

func TestPublicKeyToJWK(t *testing.T) {
	t.Run("RSA", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateRSA2048Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, jwa.RSA, jwk.KeyType())

		jwk2, err := PublicKeyToJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, jwa.RSA, jwk2.KeyType())
	})

	t.Run("Ed25519", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, jwa.OKP, jwk.KeyType())

		jwk2, err := PublicKeyToJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, jwa.OKP, jwk2.KeyType())
	})

	t.Run("X25519", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateX25519Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, jwa.OKP, jwk.KeyType())

		jwk2, err := PublicKeyToJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, jwa.OKP, jwk2.KeyType())
	})

	t.Run("secp256k1", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateSECP256k1Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, jwa.EC, jwk.KeyType())

		jwk2, err := PublicKeyToJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, jwa.EC, jwk2.KeyType())
	})

	t.Run("ecdsa P-256", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateP256Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, jwa.EC, jwk.KeyType())

		jwk2, err := PublicKeyToJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, jwa.EC, jwk.KeyType())
	})

	t.Run("ecdsa P-384", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateP384Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, jwa.EC, jwk.KeyType())

		jwk2, err := PublicKeyToJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, jwa.EC, jwk2.KeyType())
	})

	t.Run("unsupported", func(tt *testing.T) {
		jwk, err := PublicKeyToJWK(nil)
		assert.Error(tt, err)
		assert.Empty(tt, jwk)
	})
}

func TestPublicKeyToPublicKeyJWK(t *testing.T) {
	t.Run("RSA", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateRSA2048Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "RSA", jwk.KTY)

		jwk2, err := PublicKeyToPublicKeyJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "RSA", jwk2.KTY)
	})

	t.Run("Ed25519", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "OKP", jwk2.KTY)
		assert.Equal(tt, "Ed25519", jwk2.CRV)
	})

	t.Run("X25519", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateX25519Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "OKP", jwk2.KTY)
		assert.Equal(tt, "Ed25519", jwk2.CRV)
	})

	t.Run("secp256k1", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateSECP256k1Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "secp256k1", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "EC", jwk2.KTY)
		assert.Equal(tt, "secp256k1", jwk2.CRV)
	})

	t.Run("ecdsa P-256", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateP256Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-256", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "EC", jwk2.KTY)
		assert.Equal(tt, "P-256", jwk2.CRV)
	})

	t.Run("ecdsa P-384", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateP384Key()
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-384", jwk.CRV)

		jwk2, err := PublicKeyToPublicKeyJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, "EC", jwk2.KTY)
		assert.Equal(tt, "P-384", jwk2.CRV)
	})

	t.Run("Dilithium 2", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium2)
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, jwk.Alg)

		jwk2, err := PublicKeyToPublicKeyJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, jwk2.Alg)
	})

	t.Run("Dilithium 3", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium3)
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, jwk.Alg)

		jwk2, err := PublicKeyToPublicKeyJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, jwk2.Alg)
	})

	t.Run("Dilithium 5", func(tt *testing.T) {
		pubKey, _, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium5)
		assert.NoError(t, err)

		jwk, err := PublicKeyToPublicKeyJWK(pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, jwk.Alg)

		jwk2, err := PublicKeyToPublicKeyJWK(&pubKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, jwk2.Alg)
	})

	t.Run("unsupported", func(tt *testing.T) {
		jwk, err := PublicKeyToPublicKeyJWK(nil)
		assert.Error(tt, err)
		assert.Empty(tt, jwk)
	})
}

func TestPrivateKeyToPrivateKeyJWK(t *testing.T) {
	t.Run("RSA", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateRSA2048Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "RSA", jwk.KTY)
	})

	t.Run("Ed25519", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)
	})

	t.Run("X25519", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateX25519Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "OKP", jwk.KTY)
		assert.Equal(tt, "Ed25519", jwk.CRV)
	})

	t.Run("secp256k1", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateSECP256k1Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "secp256k1", jwk.CRV)
	})

	t.Run("ecdsa P-256", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateP256Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-256", jwk.CRV)
	})

	t.Run("ecdsa P-384", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateP384Key()
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, "EC", jwk.KTY)
		assert.Equal(tt, "P-384", jwk.CRV)
	})

	t.Run("Dilithium 2", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium2)
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, jwk.Alg)

		_, jwk2, err := PrivateKeyToPrivateKeyJWK(&privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode2Alg, jwk2.Alg)
	})

	t.Run("Dilithium 3", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium3)
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, jwk.Alg)

		_, jwk2, err := PrivateKeyToPrivateKeyJWK(&privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode3Alg, jwk2.Alg)
	})

	t.Run("Dilithium 5", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateDilithiumKeyPair(crypto.Dilithium5)
		assert.NoError(t, err)

		_, jwk, err := PrivateKeyToPrivateKeyJWK(privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk)
		assert.Equal(tt, DilithiumKTY, jwk.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, jwk.Alg)

		_, jwk2, err := PrivateKeyToPrivateKeyJWK(&privKey)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jwk2)
		assert.Equal(tt, DilithiumKTY, jwk2.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, jwk2.Alg)
	})

	t.Run("unsupported", func(tt *testing.T) {
		_, jwk, err := PrivateKeyToPrivateKeyJWK(nil)
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
		assert.EqualValues(tt, DilithiumMode5Alg, pubKeyJWK.Alg)

		gotPubKey, err := pubKeyJWK.ToPublicKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPubKey)
	})

	t.Run("Dilithium Private Key", func(tt *testing.T) {
		var privKeyJWK PrivateKeyJWK
		retrieveTestVectorAs(tt, dilithiumPrivateJWK, &privKeyJWK)
		assert.NotEmpty(tt, privKeyJWK)
		assert.Equal(tt, DilithiumKTY, privKeyJWK.KTY)
		assert.EqualValues(tt, DilithiumMode5Alg, privKeyJWK.Alg)

		gotPrivKey, err := privKeyJWK.ToPrivateKey()
		assert.NoError(tt, err)
		assert.NotEmpty(tt, gotPrivKey)
	})
}
