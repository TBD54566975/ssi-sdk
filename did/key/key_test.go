package key

import (
	"context"
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"testing"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"

	"github.com/multiformats/go-varint"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/did/resolution"

	"github.com/TBD54566975/ssi-sdk/crypto"

	"github.com/stretchr/testify/assert"
)

func TestParseDID(t *testing.T) {
	// good did
	didKey := DIDKey("did:key:abcd")
	parsed, err := didKey.Suffix()
	assert.NoError(t, err)
	assert.NotEmpty(t, parsed)

	// bad did
	badDIDKey := DIDKey("bad")
	_, err = badDIDKey.Suffix()
	assert.Error(t, err)
}

func TestCreateDIDKey(t *testing.T) {
	t.Run("Ed25519 happy path", func(t *testing.T) {
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
	})

	t.Run("Bad key type", func(t *testing.T) {
		_, _, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)

		_, err = CreateDIDKey("bad", []byte("invalid"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported did:key type: bad")
	})
}

func TestGenerateDIDKey(t *testing.T) {
	tests := []struct {
		name      string
		keyType   crypto.KeyType
		expectErr bool
	}{
		{
			name:      "Ed25519",
			keyType:   crypto.Ed25519,
			expectErr: false,
		},
		{
			name:      "x25519",
			keyType:   crypto.X25519,
			expectErr: false,
		},
		{
			name:      "SECP256k1",
			keyType:   crypto.SECP256k1,
			expectErr: false,
		},
		{
			name:      "P256",
			keyType:   crypto.P256,
			expectErr: false,
		},
		{
			name:      "P384",
			keyType:   crypto.P384,
			expectErr: false,
		},
		{
			name:      "P521",
			keyType:   crypto.P521,
			expectErr: false,
		},
		{
			name:      "RSA",
			keyType:   crypto.RSA,
			expectErr: false,
		},
		{
			name:      "Unsupported",
			keyType:   crypto.KeyType("unsupported"),
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			privKey, didKey, err := GenerateDIDKey(test.keyType)

			if test.expectErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, didKey)
			assert.NotEmpty(t, privKey)

			assert.True(t, strings.Contains(string(*didKey), "did:key"))

			codec, err := did.KeyTypeToMultiCodec(test.keyType)
			assert.NoError(t, err)

			parsed, err := didKey.Suffix()
			assert.NoError(t, err)
			encoding, decoded, err := multibase.Decode(parsed)
			assert.NoError(t, err)
			assert.True(t, encoding == did.Base58BTCMultiBase)

			multiCodec, n, err := varint.FromUvarint(decoded)
			assert.NoError(t, err)
			assert.Equal(t, 2, n)
			assert.Equal(t, codec, multicodec.Code(multiCodec))
		})
	}
}

func TestDecodeDIDKey(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		pk, sk, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)
		assert.NotEmpty(t, pk)
		assert.NotEmpty(t, sk)

		didKey, err := CreateDIDKey(crypto.Ed25519, pk)
		assert.NoError(t, err)
		assert.NotEmpty(t, didKey)

		pubKey, cryptoKeyType, err := didKey.Decode()
		assert.NoError(t, err)
		assert.NotEmpty(t, pubKey)
		assert.Equal(t, cryptoKeyType, crypto.Ed25519)
	})

	t.Run("bad DID", func(t *testing.T) {
		badDID := DIDKey("bad")
		_, _, err := badDID.Decode()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid did:key: bad")
	})

	t.Run("DID but not a valid did:key", func(t *testing.T) {
		badDID := DIDKey("did:key:bad")
		_, _, err := badDID.Decode()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected 122 encoding but found 98")
	})
}

func TestExpandDIDKey(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		pk, sk, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)
		assert.NotEmpty(t, pk)
		assert.NotEmpty(t, sk)

		didKey, err := CreateDIDKey(crypto.Ed25519, pk)
		assert.NoError(t, err)
		assert.NotEmpty(t, didKey)

		doc, err := didKey.Expand()
		assert.NoError(t, err)
		assert.NotEmpty(t, doc)
		assert.NoError(t, doc.IsValid())
	})

	t.Run("bad DID", func(t *testing.T) {
		badDID := DIDKey("bad")
		_, err := badDID.Expand()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid did:key: bad")
	})

	t.Run("DID but not a valid did:key", func(t *testing.T) {
		badDID := DIDKey("did:key:bad")
		_, err := badDID.Expand()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected 122 encoding but found 98")
	})
}

func TestGenerateAndDecodeDIDKey(t *testing.T) {
	for _, kt := range GetSupportedDIDKeyTypes() {
		privKey, didKey, err := GenerateDIDKey(kt)
		assert.NotEmpty(t, privKey)
		assert.NoError(t, err)

		pubKey, cryptoKeyType, err := didKey.Decode()
		assert.NoError(t, err)
		assert.NotEmpty(t, pubKey)
		assert.Equal(t, cryptoKeyType, kt)
	}
}

func TestGenerateAndResolveDIDKey(t *testing.T) {
	resolvers := []resolution.Resolver{Resolver{}}
	r, _ := resolution.NewResolver(resolvers...)

	for _, kt := range GetSupportedDIDKeyTypes() {
		_, didKey, err := GenerateDIDKey(kt)
		assert.NoError(t, err)

		doc, err := r.Resolve(context.Background(), didKey.String())
		assert.NoError(t, err)
		assert.NotEmpty(t, doc)
		assert.Equal(t, didKey.String(), doc.Document.ID)
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
		privKey, didKey, err := GenerateDIDKey(crypto.SECP256k1)
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
