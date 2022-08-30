package manifest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
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
				Constraints: &exchange.Constraints{
					Fields: []exchange.Field{
						{
							Path: []string{".vc.id"},
						},
					},
				},
			},
		},
	})
	assert.NoError(t, err)

	manifest, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, manifest)
}

func TestCredentialApplicationBuilder(t *testing.T) {
	builder := NewCredentialApplicationBuilder("manifest-id")
	_, err := builder.Build()
	assert.Error(t, err)
	notReadyErr := "credential application not ready to be built"
	assert.Contains(t, err.Error(), notReadyErr)

	assert.False(t, builder.IsEmpty())

	err = builder.SetApplicationManifestID("manifest-id")
	assert.NoError(t, err)

	// set bad claim format
	err = builder.SetApplicationClaimFormat(exchange.ClaimFormat{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set claim format with no values")

	// set good claim format
	err = builder.SetApplicationClaimFormat(exchange.ClaimFormat{
		JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
	})
	assert.NoError(t, err)

	// set bad submission
	err = builder.SetPresentationSubmission(exchange.PresentationSubmission{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set invalid presentation submission")

	// set good submission
	err = builder.SetPresentationSubmission(exchange.PresentationSubmission{
		ID:           "submission-id",
		DefinitionID: "definition-id",
		DescriptorMap: []exchange.SubmissionDescriptor{
			{
				ID:     "descriptor-id",
				Format: "jwt",
				Path:   "descriptor-path",
			},
		},
	})
	assert.NoError(t, err)

	application, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, application)
}

func TestCredentialResponseBuilder(t *testing.T) {
	builder := NewCredentialResponseBuilder("manifest-id")
	_, err := builder.Build()
	assert.Error(t, err)
	notReadyErr := "credential response not ready to be built"
	assert.Contains(t, err.Error(), notReadyErr)

	assert.False(t, builder.IsEmpty())

	err = builder.SetManifestID("manifest-id")
	assert.NoError(t, err)

	err = builder.SetApplicationID("application-id")
	assert.NoError(t, err)

	// bad map
	err = builder.SetFulfillment(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set no submission descriptors")

	// another bad map
	err = builder.SetFulfillment([]exchange.SubmissionDescriptor{
		{
			ID:   "bad",
			Path: "bad",
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set descriptor map; invalid descriptor")

	// good map
	err = builder.SetFulfillment([]exchange.SubmissionDescriptor{
		{
			ID:     "descriptor-id",
			Format: "jwt",
			Path:   "path",
		},
	})
	assert.NoError(t, err)

	fulfillment, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, fulfillment)
}
