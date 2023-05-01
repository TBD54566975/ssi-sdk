package did

import (
	"context"
	"embed"
	"strings"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
)

const (
	P256Vector   string = "did-jwk-p256.json"
	X25519Vector string = "did-jwk-x25519.json"
)

var (
	//go:embed testdata
	jwkTestVectors embed.FS
	jwkVectors     = []string{P256Vector, X25519Vector}
)

// from https://github.com/quartzjer/did-jwk/blob/main/spec.md#examples
func TestDIDJWKVectors(t *testing.T) {
	t.Run("P-256", func(tt *testing.T) {
		did := "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
		didJWK := DIDJWK(did)
		valid := didJWK.IsValid()
		assert.True(tt, valid)

		gotTestVector, err := getTestVector(P256Vector)
		assert.NoError(t, err)
		var didDoc Document
		err = json.Unmarshal([]byte(gotTestVector), &didDoc)
		assert.NoError(tt, err)

		ourDID, err := didJWK.Expand()
		assert.NoError(tt, err)

		// turn into json and compare
		ourDIDJSON, err := json.Marshal(ourDID)
		assert.NoError(tt, err)
		didDocJSON, err := json.Marshal(didDoc)
		assert.NoError(tt, err)
		assert.JSONEq(tt, string(ourDIDJSON), string(didDocJSON))
	})

	t.Run("X25519", func(tt *testing.T) {
		did := "did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ1c2UiOiJlbmMiLCJ4IjoiM3A3YmZYdDl3YlRUVzJIQzdPUTFOei1EUThoYmVHZE5yZngtRkctSUswOCJ9"
		didJWK := DIDJWK(did)
		valid := didJWK.IsValid()
		assert.True(tt, valid)

		gotTestVector, err := getTestVector(X25519Vector)
		assert.NoError(t, err)
		var didDoc Document
		err = json.Unmarshal([]byte(gotTestVector), &didDoc)
		assert.NoError(tt, err)

		ourDID, err := didJWK.Expand()
		assert.NoError(tt, err)

		// turn into json and compare
		ourDIDJSON, err := json.Marshal(ourDID)
		assert.NoError(tt, err)
		didDocJSON, err := json.Marshal(didDoc)
		assert.NoError(tt, err)

		assert.JSONEq(tt, string(ourDIDJSON), string(didDocJSON))
	})
}

func TestGenerateDIDJWK(t *testing.T) {
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
			privKey, didJWK, err := GenerateDIDJWK(test.keyType)

			if test.expectErr {
				assert.Error(t, err)
				return
			}

			jsonWebKey, err := cryptosuite.JSONWebKey2020FromPrivateKey(privKey)
			assert.NoError(t, err)
			assert.NotEmpty(t, jsonWebKey)

			assert.NoError(t, err)
			assert.NotNil(t, didJWK)
			assert.NotEmpty(t, privKey)

			assert.True(t, strings.Contains(string(*didJWK), "did:jwk"))
		})
	}
}

func TestExpandDIDJWK(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		pk, sk, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)
		assert.NotEmpty(t, pk)
		assert.NotEmpty(t, sk)

		gotJWK, err := jwk.FromRaw(sk)
		assert.NoError(t, err)

		didJWK, err := CreateDIDJWK(gotJWK)
		assert.NoError(t, err)
		assert.NotEmpty(t, didJWK)

		doc, err := didJWK.Expand()
		assert.NoError(t, err)
		assert.NotEmpty(t, doc)
		assert.NoError(t, doc.IsValid())
	})

	t.Run("bad DID returns error ", func(t *testing.T) {
		badDID := DIDJWK("bad")
		_, err := badDID.Expand()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid did:jwk: bad")
	})

	t.Run("DID but not a valid did:jwk", func(t *testing.T) {
		badDID := DIDKey("did:jwk:bad")
		_, err := badDID.Expand()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not parse did:key: invalid did:key: did:jwk:bad")
	})
}

func TestGenerateAndResolveDIDJWK(t *testing.T) {
	resolvers := []Resolver{JWKResolver{}}
	resolver, _ := NewResolver(resolvers...)

	for _, kt := range GetSupportedDIDJWKTypes() {
		_, didJWK, err := GenerateDIDJWK(kt)
		assert.NoError(t, err)

		doc, err := resolver.Resolve(context.Background(), didJWK.String())
		assert.NoError(t, err)
		assert.NotEmpty(t, doc)
		assert.Equal(t, didJWK.String(), doc.Document.ID)
	}
}
