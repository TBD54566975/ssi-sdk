package exchange

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/crypto"
)

func TestPresentationDefinitionBuilder(t *testing.T) {

}

func TestInputDescriptorBuilder(t *testing.T) {
	builder := NewInputDescriptorBuilder()
	_, err := builder.Build()

	// since an input descriptor only needs an ID, this will be valid
	assert.NoError(t, err)
	assert.False(t, builder.IsEmpty())

	err = builder.SetName("test name")
	assert.NoError(t, err)

	err = builder.SetPurpose("purpose")
	assert.NoError(t, err)

	// set empty claim format - error
	err = builder.SetClaimFormat(ClaimFormat{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set claim format with no values")

	// valid claim format
	err = builder.SetClaimFormat(ClaimFormat{
		JWT: &JWTType{
			Alg: []crypto.SignatureAlgorithm{crypto.EdDSA},
		},
	})
	assert.NoError(t, err)

	// set invalid constraints, field with no path
	requiredPref := Required
	err = builder.SetConstraints(Constraints{
		Fields: []Field{
			{
				ID: "bad",
			},
		},
		LimitDisclosure: &requiredPref,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set invalid constraints")

	err = builder.SetConstraints(Constraints{
		Fields: []Field{
			{
				Path: []string{"path"},
				ID:   "field-id",
			},
		},
		LimitDisclosure: &requiredPref,
	})
	assert.NoError(t, err)

	// set empty group - error
	err = builder.SetGroup(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set empty group")

	// valid group
	err = builder.SetGroup([]string{"test-group"})
	assert.NoError(t, err)

	inputDescriptor, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, inputDescriptor)
}

func TestPresentationSubmissionBuilder(t *testing.T) {
	builder := NewPresentationSubmissionBuilder("test-definition-id")
	_, err := builder.Build()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "presentation submission not ready to be built")

	// no submission descriptors - error
	err = builder.SetDescriptorMap(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set empty descriptors")

	// invalid descriptors, missing id - error
	err = builder.SetDescriptorMap([]SubmissionDescriptor{
		{
			Format: "format",
			Path:   "path",
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set descriptor map; invalid submission descriptor")

	// invalid descriptors, missing nested id - error
	err = builder.SetDescriptorMap([]SubmissionDescriptor{
		{
			ID:     "id",
			Format: "format",
			Path:   "path",
			PathNested: &SubmissionDescriptor{
				Format: "format-nested",
				Path:   "path-nested",
			},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set descriptor map; invalid submission descriptor")

	// valid descriptors
	err = builder.SetDescriptorMap([]SubmissionDescriptor{
		{
			ID:     "id",
			Format: "jwt",
			Path:   "path",
			PathNested: &SubmissionDescriptor{
				ID:     "id-nested",
				Format: "jwt",
				Path:   "path-nested",
			},
		},
	})
	assert.NoError(t, err)

	presentationSubmission, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, presentationSubmission)
}
