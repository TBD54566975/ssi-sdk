package did

import (
	"testing"

	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
)

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

	t.Run("doc with no validation methods", func(t *testing.T) {
		doc := Document{ID: "test-did"}
		_, err := GetKeyFromVerificationMethod(doc, "test-kid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "has no validation methods")
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
		assert.Contains(t, err.Error(), "no validation methods with kid: test-kid")
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
		assert.Contains(t, err.Error(), "no public key found in validation method")
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

	t.Run("doc for did with multibase key", func(t *testing.T) {
		doc := Document{
			ID: "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
			VerificationMethod: []VerificationMethod{
				{
					ID:              "#z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
					Type:            "Ed25519VerificationKey2018",
					Controller:      "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
					PublicKeyBase58: "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS",
				},
			},
		}

		key, err := GetKeyFromVerificationMethod(doc, doc.VerificationMethod[0].ID)
		assert.NoError(t, err)
		assert.NotEmpty(t, key)
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
