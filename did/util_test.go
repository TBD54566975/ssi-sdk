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

	t.Run("doc with fully qualified kid and #", func(t *testing.T) {
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
		key, err := GetKeyFromVerificationMethod(doc, "test-did#test-kid")
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

	t.Run("doc without fully qualified kid, but kid is fully qualified", func(t *testing.T) {
		pubKey, _, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)
		b58PubKey := base58.Encode(pubKey)
		docWithHash := Document{
			ID: "test-did",
			VerificationMethod: []VerificationMethod{
				{
					ID:              "#test-kid",
					Type:            "Ed25519VerificationKey2018",
					PublicKeyBase58: b58PubKey,
				},
			},
		}

		key, err := GetKeyFromVerificationMethod(docWithHash, "test-did#test-kid")
		assert.NoError(t, err)
		assert.Equal(t, pubKey, key)

		docWithHash.VerificationMethod[0].ID = "test-kid"
		docWithoutHash := docWithHash
		key, err = GetKeyFromVerificationMethod(docWithoutHash, "test-did#test-kid")
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

func TestFullyQualifiedVerificationMethodID(t *testing.T) {
	type args struct {
		did                  string
		verificationMethodID string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "simple did simple verification id",
			args: args{
				did:                  "did:key:hello",
				verificationMethodID: "123456",
			},
			want: "did:key:hello#123456",
		},
		{
			name: "simple did hashed verification id",
			args: args{
				did:                  "did:key:hello",
				verificationMethodID: "#123456",
			},
			want: "did:key:hello#123456",
		},
		{
			name: "simple did full verification id",
			args: args{
				did:                  "did:key:hello",
				verificationMethodID: "did:key:hello#123456",
			},
			want: "did:key:hello#123456",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, FullyQualifiedVerificationMethodID(tt.args.did, tt.args.verificationMethodID), "FullyQualifiedVerificationMethodID(%v, %v)", tt.args.did, tt.args.verificationMethodID)
		})
	}
}
