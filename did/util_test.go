package did

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveKeyForDID(t *testing.T) {
	resolver, err := NewResolver([]Resolver{KeyResolver{}}...)
	require.NoError(t, err)
	require.NotEmpty(t, resolver)

	t.Run("empty resolver", func(tt *testing.T) {
		_, err := ResolveKeyForDID(context.Background(), nil, "did:test", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "resolver cannot be empty")
	})

	t.Run("empty did", func(tt *testing.T) {
		_, err := ResolveKeyForDID(context.Background(), resolver, "", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "not a valid did")
	})

	t.Run("unresolveable did", func(tt *testing.T) {
		_, err := ResolveKeyForDID(context.Background(), resolver, "did:example:test", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported method: example")
	})

	t.Run("unresolveable did", func(tt *testing.T) {
		_, err := ResolveKeyForDID(context.Background(), resolver, "did:example:test", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "unsupported method: example")
	})

	t.Run("invalid did", func(tt *testing.T) {
		_, err := ResolveKeyForDID(context.Background(), resolver, "did:key:test", "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "could not expand did:key DID")
	})

	t.Run("valid did; no kid", func(tt *testing.T) {
		_, didKey, err := GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		_, err = ResolveKeyForDID(context.Background(), resolver, didKey.String(), "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "has no verification methods with kid: test-kid")
	})

	t.Run("valid did; valid kid", func(tt *testing.T) {
		privKey, didKey, err := GenerateDIDKey(crypto.Ed25519)
		assert.NoError(tt, err)
		expanded, err := didKey.Expand()
		assert.NoError(tt, err)
		kid := expanded.VerificationMethod[0].ID

		key, err := ResolveKeyForDID(context.Background(), resolver, didKey.String(), kid)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, key)

		pubKey := privKey.(ed25519.PrivateKey).Public()
		assert.Equal(tt, pubKey, key)
	})
}

func TestGetKeyFromVerificationInformation(t *testing.T) {
	t.Run("empty doc", func(tt *testing.T) {
		_, err := GetKeyFromVerificationMethod(Document{}, "test-kid")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "did doc cannot be empty")
	})

	t.Run("no kid", func(tt *testing.T) {
		_, err := GetKeyFromVerificationMethod(Document{ID: "id"}, "")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "kid is required")
	})

	t.Run("doc with no verification methods", func(t *testing.T) {
		doc := Document{ID: "test-did"}
		_, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "has no verification methods")
	})

	t.Run("doc without specified kid", func(t *testing.T) {
		doc := Document{
			ID: "test-did",
			VerificationMethod: []VerificationMethod{
				{
					ID:              "#test-kid-2",
					Type:            "Ed25519VerificationKey2018",
					PublicKeyBase58: "test-key",
				},
			},
		}
		_, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no verification methods with kid: test-kid")
	})

	t.Run("doc with specified kid, bad multibase key", func(t *testing.T) {
		doc := Document{
			ID: "test-did",
			VerificationMethod: []VerificationMethod{
				{
					ID:                 "#test-kid",
					Type:               "Ed25519VerificationKey2018",
					PublicKeyMultibase: "test-key",
				},
			},
		}
		_, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "converting multibase key")
	})

	t.Run("doc with specified kid, bad b58 key", func(t *testing.T) {
		doc := Document{
			ID: "test-did",
			VerificationMethod: []VerificationMethod{
				{
					ID:              "#test-kid",
					Type:            "Ed25519VerificationKey2018",
					PublicKeyBase58: "test-key",
				},
			},
		}
		_, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decoding base58 key")
	})

	t.Run("doc with specified kid, bad JWK key", func(t *testing.T) {
		doc := Document{
			ID: "test-did",
			VerificationMethod: []VerificationMethod{
				{
					ID:   "#test-kid",
					Type: "Ed25519VerificationKey2018",
					PublicKeyJWK: &jwx.PublicKeyJWK{
						KID: "bad",
					},
				},
			},
		}
		_, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parsing jwk")
	})

	t.Run("doc with specified kid, no public key", func(t *testing.T) {
		doc := Document{
			ID: "test-did",
			VerificationMethod: []VerificationMethod{
				{
					ID:   "#test-kid",
					Type: "Ed25519VerificationKey2018",
				},
			},
		}
		_, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no public key found in verification method")
	})

	t.Run("doc with unqualified kid", func(t *testing.T) {
		pubKey, _, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)
		b58PubKey := base58.Encode(pubKey)
		doc := Document{
			ID: "test-did",
			VerificationMethod: []VerificationMethod{
				{
					ID:              "test-kid",
					Type:            "Ed25519VerificationKey2018",
					PublicKeyBase58: b58PubKey,
				},
			},
		}
		key, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.NoError(t, err)
		assert.Equal(t, pubKey, key)
	})

	t.Run("doc with unqualified kid and #", func(t *testing.T) {
		pubKey, _, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)
		b58PubKey := base58.Encode(pubKey)
		doc := Document{
			ID: "test-did",
			VerificationMethod: []VerificationMethod{
				{
					ID:              "#test-kid",
					Type:            "Ed25519VerificationKey2018",
					PublicKeyBase58: b58PubKey,
				},
			},
		}
		key, err := GetKeyFromVerificationMethod(doc, "#test-kid")
		assert.NoError(t, err)
		assert.Equal(t, pubKey, key)

		key, err = GetKeyFromVerificationMethod(doc, "test-kid")
		assert.NoError(t, err)
		assert.Equal(t, pubKey, key)
	})

	t.Run("doc with fully qualified kid", func(t *testing.T) {
		pubKey, _, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)
		b58PubKey := base58.Encode(pubKey)
		doc := Document{
			ID: "test-did",
			VerificationMethod: []VerificationMethod{
				{
					ID:              "test-did#test-kid",
					Type:            "Ed25519VerificationKey2018",
					PublicKeyBase58: b58PubKey,
				},
			},
		}
		key, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.NoError(t, err)
		assert.Equal(t, pubKey, key)

		key, err = GetKeyFromVerificationMethod(doc, "#test-kid")
		assert.NoError(t, err)
		assert.Equal(t, pubKey, key)

		key, err = GetKeyFromVerificationMethod(doc, "test-did#test-kid")
		assert.NoError(t, err)
		assert.Equal(t, pubKey, key)
	})

	t.Run("doc for did:key with multibase key", func(t *testing.T) {
		privKey, didKey, err := GenerateDIDKey(crypto.Ed25519)
		assert.NoError(t, err)
		pubKey := privKey.(ed25519.PrivateKey).Public()

		doc, err := didKey.Expand()
		assert.NoError(t, err)
		assert.NotNil(t, doc)

		key, err := GetKeyFromVerificationMethod(*doc, doc.VerificationMethod[0].ID)
		assert.NoError(t, err)
		assert.Equal(t, pubKey, key)
	})

	t.Run("doc for did with JWK", func(t *testing.T) {
		doc := Document{
			ID: "did:example:123",
			VerificationMethod: []VerificationMethod{
				{
					ID:   "did:example:123#test-kid",
					Type: "JsonWebKey2020",
					PublicKeyJWK: &jwx.PublicKeyJWK{
						KTY: "OKP",
						CRV: "Ed25519",
						X:   "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
					},
				},
			},
		}
		key, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.NoError(t, err)
		assert.NotEmpty(t, key)

		key, err = GetKeyFromVerificationMethod(doc, "#test-kid")
		assert.NoError(t, err)
		assert.NotEmpty(t, key)

		key, err = GetKeyFromVerificationMethod(doc, "did:example:123#test-kid")
		assert.NoError(t, err)
		assert.NotEmpty(t, key)
	})
}

func TestEncodePublicKeyWithKeyMultiCodecType(t *testing.T) {
	// unsupported type
	_, err := encodePublicKeyWithKeyMultiCodecType(crypto.KeyType("unsupported"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a supported key type")

	// bad public key
	_, err = encodePublicKeyWithKeyMultiCodecType(crypto.Ed25519, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown public key type; could not convert to bytes")
}
