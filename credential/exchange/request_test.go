package exchange

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestBuildPresentationRequest(t *testing.T) {
	t.Run("JWT Request", func(t *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)

		signer, err := crypto.NewJWTSigner("test-id", privKey)
		assert.NoError(t, err)

		testDef := getDummyPresentationDefinition()
		requestJWTBytes, err := BuildJWTPresentationRequest(*signer, testDef, "did:test")
		assert.NoError(t, err)
		assert.NotEmpty(t, requestJWTBytes)

		verifier, err := signer.ToVerifier()
		assert.NoError(t, err)

		parsed, err := verifier.VerifyAndParse(string(requestJWTBytes))
		assert.NoError(t, err)

		presDef, ok := parsed.Get(PresentationDefinitionKey)
		assert.True(t, ok)
		jsonEq(t, testDef, presDef)
	})

	t.Run("Happy Path", func(t *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)

		signer, err := crypto.NewJWTSigner("test-id", privKey)
		assert.NoError(t, err)

		testDef := getDummyPresentationDefinition()
		requestJWTBytes, err := BuildPresentationRequest(*signer, JWTRequest, testDef)
		assert.NoError(t, err)
		assert.NotEmpty(t, requestJWTBytes)

		verifier, err := signer.ToVerifier()
		assert.NoError(t, err)

		parsed, err := verifier.VerifyAndParse(string(requestJWTBytes))
		assert.NoError(t, err)

		presDef, ok := parsed.Get(PresentationDefinitionKey)
		assert.True(t, ok)
		jsonEq(t, testDef, presDef)
	})

	t.Run("Unsupported Request Methods", func(t *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(t, err)

		signer, err := crypto.NewJWTSigner("test-id", privKey)
		assert.NoError(t, err)

		testDef := getDummyPresentationDefinition()
		_, err = BuildPresentationRequest(*signer, "bad", testDef, PresentationRequestOption{
			Type:  TargetOption,
			Value: "did:test:abcd",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported presentation request type")
	})
}

func getDummyPresentationDefinition() PresentationDefinition {
	return PresentationDefinition{
		ID: "test-id",
		InputDescriptors: []InputDescriptor{
			{
				ID:      "test-input-descriptor-id",
				Name:    "test-input-descriptor",
				Purpose: "because!",
			},
		},
		Name: "test-def",
		Format: &ClaimFormat{
			JWTVC: &JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		},
	}
}

// turn two objects into json and compare value equality
func jsonEq(t *testing.T, a any, b any) {
	aBytes, err := json.Marshal(a)
	assert.NoError(t, err)
	bBytes, err := json.Marshal(b)
	assert.NoError(t, err)
	assert.JSONEq(t, string(aBytes), string(bBytes))
}
