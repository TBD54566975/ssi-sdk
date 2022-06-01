package manifest

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCredentialManifestBuilder(t *testing.T) {
	builder := NewCredentialManifestBuilder()
	_, err := builder.Build()
	assert.Error(t, err)
	notReadyErr := "credential manifest not ready to be built"
	assert.Contains(t, err.Error(), notReadyErr)

	assert.False(t, builder.IsEmpty())

	// set a bad issuer
	err = builder.SetIssuer(Issuer{
		Name: "Satoshi",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set invalid issuer")

	// good issuer
	err = builder.SetIssuer(Issuer{
		ID:   "did:abcd:test",
		Name: "Satoshi",
	})
	assert.NoError(t, err)

	// no descriptors
	err = builder.SetOutputDescriptors(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set no output descriptors")

	// set bad output descriptors - first is good, second is bad
	descriptors := []OutputDescriptor{
		{
			ID:          "id1",
			Schema:      "schema1",
			Name:        "good ID",
			Description: "it's all good",
		},
		{
			Description: "no good",
		},
	}
	err = builder.SetOutputDescriptors(descriptors)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set output descriptors; invalid descriptor")

	// good descriptors
	descriptors = []OutputDescriptor{
		{
			ID:          "id1",
			Schema:      "https://test.com/schema",
			Name:        "good ID",
			Description: "it's all good",
		},
		{
			ID:          "id2",
			Schema:      "https://test.com/schema",
			Name:        "good ID",
			Description: "it's all good",
		},
	}
	err = builder.SetOutputDescriptors(descriptors)
	assert.NoError(t, err)

	// bad format
	err = builder.SetClaimFormat(exchange.ClaimFormat{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set claim format with no values")

	// good format
	err = builder.SetClaimFormat(exchange.ClaimFormat{
		JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
	})
	assert.NoError(t, err)

	// bad presentation definition
	err = builder.SetPresentationDefinition(exchange.PresentationDefinition{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set empty presentation definition")

	// good presentation definition
	err = builder.SetPresentationDefinition(exchange.PresentationDefinition{
		ID: "pres-def-id",
		InputDescriptors: []exchange.InputDescriptor{
			{
				ID: "test-id",
			},
		},
	})
	assert.NoError(t, err)

	manifest, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, manifest)
}

func TestCredentialApplicationBuilder(t *testing.T) {

}

func TestCredentialFulfillmentBuilder(t *testing.T) {

}
