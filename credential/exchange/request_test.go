package exchange

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
)

func TestBuildPresentationRequest(t *testing.T) {

	t.Run("JWT Request", func(t *testing.T) {
		jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
		assert.NoError(t, err)
		signer, err := cryptosuite.NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, cryptosuite.Authentication)
		assert.NoError(t, err)

		testDef := getDummyPresentationDefinition()
		requestJWTBytes, err := BuildJWTPresentationRequest(*signer, testDef, "did:test")
		assert.NoError(t, err)
		assert.NotEmpty(t, requestJWTBytes)

		verifier, err := cryptosuite.NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
		assert.NoError(t, err)

		parsed, err := verifier.VerifyAndParseJWT(string(requestJWTBytes))
		assert.NoError(t, err)

		presDef, ok := parsed.Get(PresentationDefinitionKey)
		assert.True(t, ok)
		jsonEq(t, testDef, presDef)
	})

	t.Run("Happy Path", func(t *testing.T) {
		jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
		assert.NoError(t, err)
		signer, err := cryptosuite.NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, cryptosuite.Authentication)
		assert.NoError(t, err)

		testDef := getDummyPresentationDefinition()
		requestJWTBytes, err := BuildPresentationRequest(signer, JWTRequest, testDef, "did:test")
		assert.NoError(t, err)
		assert.NotEmpty(t, requestJWTBytes)

		verifier, err := cryptosuite.NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
		assert.NoError(t, err)

		parsed, err := verifier.VerifyAndParseJWT(string(requestJWTBytes))
		assert.NoError(t, err)

		presDef, ok := parsed.Get(PresentationDefinitionKey)
		assert.True(t, ok)
		jsonEq(t, testDef, presDef)
	})

	t.Run("Unsupported Request Method", func(t *testing.T) {
		jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
		assert.NoError(t, err)
		signer, err := cryptosuite.NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, cryptosuite.Authentication)
		assert.NoError(t, err)

		testDef := getDummyPresentationDefinition()
		_, err = BuildPresentationRequest(signer, "bad", testDef, "did:test")
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
func jsonEq(t *testing.T, a interface{}, b interface{}) {
	aBytes, err := json.Marshal(a)
	assert.NoError(t, err)
	bBytes, err := json.Marshal(b)
	assert.NoError(t, err)
	assert.JSONEq(t, string(aBytes), string(bBytes))
}
