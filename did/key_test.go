//go:build jwx_es256k

package did

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/TBD54566975/did-sdk/cryptosuite"

	"github.com/multiformats/go-multicodec"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-varint"

	"github.com/TBD54566975/did-sdk/crypto"

	"github.com/stretchr/testify/assert"
)

func TestCreateDIDKey(t *testing.T) {
	pk, sk, err := crypto.GenerateEd25519Key()
	assert.NoError(t, err)
	assert.NotEmpty(t, pk)
	assert.NotEmpty(t, sk)

	didKey, err := CreateDIDKey(crypto.Ed25519, pk)
	assert.NoError(t, err)
	assert.NotEmpty(t, didKey)

	didDoc, err := didKey.Expand()
	assert.NoError(t, err)
	assert.NotEmpty(t, didDoc)
	assert.Equal(t, string(*didKey), didDoc.ID)
}

func TestGenerateDIDKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType crypto.KeyType
	}{
		{
			name:    "Ed25519",
			keyType: crypto.Ed25519,
		},
		{
			name:    "x25519",
			keyType: crypto.X25519,
		},
		{
			name:    "Secp256k1",
			keyType: crypto.Secp256k1,
		},
		{
			name:    "P256",
			keyType: crypto.P256,
		},
		{
			name:    "P384",
			keyType: crypto.P384,
		},
		{
			name:    "P521",
			keyType: crypto.P521,
		},
		{
			name:    "RSA",
			keyType: crypto.RSA,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			privKey, didKey, err := GenerateDIDKey(test.keyType)
			assert.NoError(t, err)
			assert.NotNil(t, didKey)
			assert.NotEmpty(t, privKey)

			assert.True(t, strings.Contains(string(*didKey), "did:key"))

			codec, err := keyTypeToMultiCodec(test.keyType)
			assert.NoError(t, err)

			encoding, decoded, err := multibase.Decode(didKey.Parse())
			assert.NoError(t, err)
			assert.True(t, encoding == Base58BTCMultiBase)

			multiCodec, n, err := varint.FromUvarint(decoded)
			assert.NoError(t, err)
			assert.Equal(t, 2, n)
			assert.Equal(t, codec, multicodec.Code(multiCodec))
		})
	}
}

func TestDIDKeySignVerify(t *testing.T) {
	t.Run("Test Ed25519 did:key", func(t *testing.T) {
		privKey, didKey, err := GenerateDIDKey(crypto.Ed25519)
		assert.NoError(t, err)
		assert.NotNil(t, didKey)
		assert.NotEmpty(t, privKey)

		ed25519PrivKey, ok := privKey.(ed25519.PrivateKey)
		assert.True(t, ok)
		ed25519PubKey, ok := ed25519PrivKey.Public().(ed25519.PublicKey)
		assert.True(t, ok)

		msg := []byte("hello world")
		signature := ed25519.Sign(ed25519PrivKey, msg)
		verified := ed25519.Verify(ed25519PubKey, msg, signature)
		assert.True(t, verified)
	})

	t.Run("Test secp256k1 did:key", func(t *testing.T) {
		privKey, didKey, err := GenerateDIDKey(crypto.Secp256k1)
		assert.NoError(t, err)
		assert.NotNil(t, didKey)
		assert.NotEmpty(t, privKey)

		secp256k1PrivKey, ok := privKey.(secp.PrivateKey)
		assert.True(t, ok)

		ecdsaPrivKey := secp256k1PrivKey.ToECDSA()
		ecdsaPubKey := ecdsaPrivKey.PublicKey

		msg := []byte("hello world")
		digest := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivKey, digest[:])
		assert.NoError(t, err)

		verified := ecdsa.Verify(&ecdsaPubKey, digest[:], r, s)
		assert.True(t, verified)
	})

	t.Run("Test P-256 did:key", func(t *testing.T) {
		privKey, didKey, err := GenerateDIDKey(crypto.P256)
		assert.NoError(t, err)
		assert.NotNil(t, didKey)
		assert.NotEmpty(t, privKey)

		ecdsaPrivKey, ok := privKey.(ecdsa.PrivateKey)
		assert.True(t, ok)

		ecdsaPubKey := ecdsaPrivKey.PublicKey

		msg := []byte("hello world")
		digest := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, &ecdsaPrivKey, digest[:])
		assert.NoError(t, err)

		verified := ecdsa.Verify(&ecdsaPubKey, digest[:], r, s)
		assert.True(t, verified)
	})

	t.Run("Test P-384 did:key", func(t *testing.T) {
		privKey, didKey, err := GenerateDIDKey(crypto.P384)
		assert.NoError(t, err)
		assert.NotNil(t, didKey)
		assert.NotEmpty(t, privKey)

		ecdsaPrivKey, ok := privKey.(ecdsa.PrivateKey)
		assert.True(t, ok)

		ecdsaPubKey := ecdsaPrivKey.PublicKey

		msg := []byte("hello world")
		digest := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, &ecdsaPrivKey, digest[:])
		assert.NoError(t, err)

		verified := ecdsa.Verify(&ecdsaPubKey, digest[:], r, s)
		assert.True(t, verified)
	})

	t.Run("Test P-521 did:key", func(t *testing.T) {
		privKey, didKey, err := GenerateDIDKey(crypto.P521)
		assert.NoError(t, err)
		assert.NotNil(t, didKey)
		assert.NotEmpty(t, privKey)

		ecdsaPrivKey, ok := privKey.(ecdsa.PrivateKey)
		assert.True(t, ok)

		ecdsaPubKey := ecdsaPrivKey.PublicKey

		msg := []byte("hello world")
		digest := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, &ecdsaPrivKey, digest[:])
		assert.NoError(t, err)

		verified := ecdsa.Verify(&ecdsaPubKey, digest[:], r, s)
		assert.True(t, verified)
	})

	t.Run("Test RSA 2048 did:key", func(t *testing.T) {
		privKey, didKey, err := GenerateDIDKey(crypto.RSA)
		assert.NoError(t, err)
		assert.NotNil(t, didKey)
		assert.NotEmpty(t, privKey)

		rsaPrivKey, ok := privKey.(rsa.PrivateKey)
		assert.True(t, ok)
		rsaPubKey := rsaPrivKey.PublicKey

		msg := []byte("hello world")
		digest := sha256.Sum256(msg)
		signature, err := rsa.SignPKCS1v15(rand.Reader, &rsaPrivKey, gocrypto.SHA256, digest[:])
		assert.NoError(t, err)
		assert.NotEmpty(t, signature)

		err = rsa.VerifyPKCS1v15(&rsaPubKey, gocrypto.SHA256, digest[:], signature)
		assert.NoError(t, err)
	})
}

// From https://w3c-ccg.github.io/did-method-key/#test-vectors
func TestKnownTestVectors(t *testing.T) {
	t.Run("Ed25519 / X25519", func(tt *testing.T) {
		did1 := "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
		didKey1 := DIDKey(did1)
		didDoc1, err := didKey1.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did1, didDoc1.ID)
		assert.Equal(tt, 1, len(didDoc1.VerificationMethod))
		assert.Equal(tt, Ed25519VerificationKey2018, didDoc1.VerificationMethod[0].Type)

		did2 := "did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG"
		didKey2 := DIDKey(did2)
		didDoc2, err := didKey2.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did2, didDoc2.ID)
		assert.Equal(tt, 1, len(didDoc2.VerificationMethod))
		assert.Equal(tt, Ed25519VerificationKey2018, didDoc2.VerificationMethod[0].Type)

		did3 := "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf"
		didKey3 := DIDKey(did3)
		didDoc3, err := didKey3.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did3, didDoc3.ID)
		assert.Equal(tt, 1, len(didDoc3.VerificationMethod))
		assert.Equal(tt, Ed25519VerificationKey2018, didDoc3.VerificationMethod[0].Type)
	})

	t.Run("X25519", func(tt *testing.T) {
		did1 := "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F"
		didKey1 := DIDKey(did1)
		didDoc1, err := didKey1.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did1, didDoc1.ID)
		assert.Equal(tt, 1, len(didDoc1.VerificationMethod))
		assert.Equal(tt, X25519KeyAgreementKey2019, didDoc1.VerificationMethod[0].Type)

		did2 := "did:key:z6LStiZsmxiK4odS4Sb6JmdRFuJ6e1SYP157gtiCyJKfrYha"
		didKey2 := DIDKey(did2)
		didDoc2, err := didKey2.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did2, didDoc2.ID)
		assert.Equal(tt, 1, len(didDoc2.VerificationMethod))
		assert.Equal(tt, X25519KeyAgreementKey2019, didDoc2.VerificationMethod[0].Type)

		did3 := "did:key:z6LSoMdmJz2Djah2P4L9taDmtqeJ6wwd2HhKZvNToBmvaczQ"
		didKey3 := DIDKey(did3)
		didDoc3, err := didKey3.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did3, didDoc3.ID)
		assert.Equal(tt, 1, len(didDoc3.VerificationMethod))
		assert.Equal(tt, X25519KeyAgreementKey2019, didDoc3.VerificationMethod[0].Type)
	})

	t.Run("Secp256k1", func(tt *testing.T) {
		did1 := "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
		didKey1 := DIDKey(did1)
		didDoc1, err := didKey1.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did1, didDoc1.ID)
		assert.Equal(tt, 1, len(didDoc1.VerificationMethod))
		assert.Equal(tt, EcdsaSecp256k1VerificationKey2019, didDoc1.VerificationMethod[0].Type)

		did2 := "did:key:zQ3shtxV1FrJfhqE1dvxYRcCknWNjHc3c5X1y3ZSoPDi2aur2"
		didKey2 := DIDKey(did2)
		didDoc2, err := didKey2.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did2, didDoc2.ID)
		assert.Equal(tt, 1, len(didDoc2.VerificationMethod))
		assert.Equal(tt, EcdsaSecp256k1VerificationKey2019, didDoc2.VerificationMethod[0].Type)

		did3 := "did:key:zQ3shZc2QzApp2oymGvQbzP8eKheVshBHbU4ZYjeXqwSKEn6N"
		didKey3 := DIDKey(did3)
		didDoc3, err := didKey3.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did3, didDoc3.ID)
		assert.Equal(tt, 1, len(didDoc3.VerificationMethod))
		assert.Equal(tt, EcdsaSecp256k1VerificationKey2019, didDoc3.VerificationMethod[0].Type)
	})

	t.Run("P-256", func(tt *testing.T) {
		did1 := "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
		didKey1 := DIDKey(did1)
		didDoc1, err := didKey1.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did1, didDoc1.ID)
		assert.Equal(tt, 1, len(didDoc1.VerificationMethod))
		assert.Equal(tt, cryptosuite.JsonWebKey2020, didDoc1.VerificationMethod[0].Type)

		did2 := "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
		didKey2 := DIDKey(did2)
		didDoc2, err := didKey2.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did2, didDoc2.ID)
		assert.Equal(tt, 1, len(didDoc2.VerificationMethod))
		assert.Equal(tt, cryptosuite.JsonWebKey2020, didDoc2.VerificationMethod[0].Type)
	})

	t.Run("P-384", func(tt *testing.T) {
		did1 := "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9"
		didKey1 := DIDKey(did1)
		didDoc1, err := didKey1.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did1, didDoc1.ID)
		assert.Equal(tt, 1, len(didDoc1.VerificationMethod))
		assert.Equal(tt, cryptosuite.JsonWebKey2020, didDoc1.VerificationMethod[0].Type)

		did2 := "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54"
		didKey2 := DIDKey(did2)
		didDoc2, err := didKey2.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did2, didDoc2.ID)
		assert.Equal(tt, 1, len(didDoc2.VerificationMethod))
		assert.Equal(tt, cryptosuite.JsonWebKey2020, didDoc2.VerificationMethod[0].Type)
	})

	t.Run("P-521", func(tt *testing.T) {
		did1 := "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7"
		didKey1 := DIDKey(did1)
		didDoc1, err := didKey1.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did1, didDoc1.ID)
		assert.Equal(tt, 1, len(didDoc1.VerificationMethod))
		assert.Equal(tt, cryptosuite.JsonWebKey2020, didDoc1.VerificationMethod[0].Type)

		did2 := "did:key:z2J9gcGdb2nEyMDmzQYv2QZQcM1vXktvy1Pw4MduSWxGabLZ9XESSWLQgbuPhwnXN7zP7HpTzWqrMTzaY5zWe6hpzJ2jnw4f"
		didKey2 := DIDKey(did2)
		didDoc2, err := didKey2.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did2, didDoc2.ID)
		assert.Equal(tt, 1, len(didDoc2.VerificationMethod))
		assert.Equal(tt, cryptosuite.JsonWebKey2020, didDoc2.VerificationMethod[0].Type)
	})

	t.Run("RSA 2048", func(tt *testing.T) {
		did1 := "did:key:zgghBUVkqmWS8e1ioRVp2WN9Vw6x4NvnE9PGAyQsPqM3fnfPf8EdauiRVfBTcVDyzhqM5FFC7ekAvuV1cJHawtfgB9wDcru1hPDobk3hqyedijhgWmsYfJCmodkiiFnjNWATE7PvqTyoCjcmrc8yMRXmFPnoASyT5beUd4YZxTE9VfgmavcPy3BSouNmASMQ8xUXeiRwjb7xBaVTiDRjkmyPD7NYZdXuS93gFhyDFr5b3XLg7Rfj9nHEqtHDa7NmAX7iwDAbMUFEfiDEf9hrqZmpAYJracAjTTR8Cvn6mnDXMLwayNG8dcsXFodxok2qksYF4D8ffUxMRmyyQVQhhhmdSi4YaMPqTnC1J6HTG9Yfb98yGSVaWi4TApUhLXFow2ZvB6vqckCNhjCRL2R4MDUSk71qzxWHgezKyDeyThJgdxydrn1osqH94oSeA346eipkJvKqYREXBKwgB5VL6WF4qAK6sVZxJp2dQBfCPVZ4EbsBQaJXaVK7cNcWG8tZBFWZ79gG9Cu6C4u8yjBS8Ux6dCcJPUTLtixQu4z2n5dCsVSNdnP1EEs8ZerZo5pBgc68w4Yuf9KL3xVxPnAB1nRCBfs9cMU6oL1EdyHbqrTfnjE8HpY164akBqe92LFVsk8RusaGsVPrMekT8emTq5y8v8CabuZg5rDs3f9NPEtogjyx49wiub1FecM5B7QqEcZSYiKHgF4mfkteT2"
		didKey1 := DIDKey(did1)
		didDoc1, err := didKey1.Expand()
		assert.NoError(tt, err)
		assert.Equal(tt, did1, didDoc1.ID)
		assert.Equal(tt, 1, len(didDoc1.VerificationMethod))
		assert.Equal(tt, cryptosuite.JsonWebKey2020, didDoc1.VerificationMethod[0].Type)
	})
}
