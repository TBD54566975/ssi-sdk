package exchange

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/util"
)

func TestPresentationDefinitionBuilder(t *testing.T) {
	builder := NewPresentationDefinitionBuilder()
	_, err := builder.Build()

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "presentation definition not ready to be built")

	// bad input descriptor
	err = builder.SetInputDescriptors([]InputDescriptor{
		{
			Name:    "bad",
			Purpose: "bad",
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set input descriptors; invalid descriptor")

	// good input descriptor
	err = builder.SetInputDescriptors([]InputDescriptor{
		{
			ID:      "id",
			Name:    "name",
			Purpose: "purpose",
			Format: &ClaimFormat{
				JWT: &JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			},
			Constraints: &Constraints{SubjectIsIssuer: Preferred.Ptr()},
		},
	})
	assert.NoError(t, err)

	err = builder.SetName("name")
	assert.NoError(t, err)

	err = builder.SetPurpose("purpose")
	assert.NoError(t, err)

	// empty format
	err = builder.SetClaimFormat(ClaimFormat{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set claim format with no values")

	// valid claim format
	err = builder.SetClaimFormat(ClaimFormat{
		JWT: &JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
	})
	assert.NoError(t, err)

	// no requirements - error
	err = builder.SetSubmissionRequirements(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set no submission requirements")

	// missing required field - rule
	err = builder.SetSubmissionRequirements([]SubmissionRequirement{
		{
			FromOption: FromOption{
				From: "A",
			},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set submission requirements; invalid requirement")

	err = builder.SetSubmissionRequirements([]SubmissionRequirement{
		{
			Rule: All,
			FromOption: FromOption{
				From: "A",
			},
		},
	})
	assert.NoError(t, err)

	// empty frame - error
	err = builder.SetFrame(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set empty frame")

	presentationDefinition, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, presentationDefinition)
}

func TestInputDescriptorBuilder(t *testing.T) {
	builder := NewInputDescriptorBuilder()
	_, err := builder.Build()

	// since an input descriptor missing a constraint
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Error:Field validation for 'Constraints' failed on the 'required' tag")
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

func TestPE(t *testing.T) {
	builder := NewPresentationDefinitionBuilder()

	// bad input descriptor
	err := builder.SetInputDescriptors([]InputDescriptor{
		{
			ID:   uuid.NewString(),
			Name: "personal-details",
			Constraints: &Constraints{
				Fields: []Field{
					{
						Path: []string{"$.vc.credentialSubject.personalDetails.firstName", "$.credentialSubject.personalDetails.firstName"},
						ID:   "first-name",
						Filter: &Filter{
							Type:      "string",
							MinLength: 1,
						},
					},
					{
						Path: []string{"$.vc.credentialSubject.personalDetails.lastName", "$.credentialSubject.personalDetails.lastName"},
						ID:   "last-name",
						Filter: &Filter{
							Type:      "string",
							MinLength: 1,
						},
					},
				},
				SubjectIsIssuer: Preferred.Ptr(),
			},
		},
		{
			ID:   uuid.NewString(),
			Name: "academic-background",
			Constraints: &Constraints{
				Fields: []Field{
					{
						Path: []string{"$.vc.credentialSubject.schoolName", "$.credentialSubject.schoolName"},
						ID:   "school-name",
						Filter: &Filter{
							Type:      "string",
							MinLength: 1,
						},
					},
					{
						Path: []string{"$.vc.credentialSubject.startYear", "$.credentialSubject.startYear"},
						ID:   "school-year-start",
						Filter: &Filter{
							Type:    "number",
							Minimum: 1900,
							Maximum: 2022,
						},
					},
					{
						Path: []string{"$.vc.credentialSubject.endYear", "$.credentialSubject.endYear"},
						ID:   "school-year-end",
						Filter: &Filter{
							Type:    "number",
							Minimum: 1900,
							Maximum: 2022,
						},
					},
				},
			},
		},
		{
			ID:   uuid.NewString(),
			Name: "children-info",
			Constraints: &Constraints{
				Fields: []Field{
					{
						Path: []string{"$.vc.credentialSubject.children[*].firstName", "$.credentialSubject.children[*].firstName"},
						ID:   "children-info-first-name",
						Filter: &Filter{
							Type:      "string",
							MinLength: 1,
						},
					},
					{
						Path: []string{"$.vc.credentialSubject.children[*].lastName", "$.credentialSubject.children[*].lastName"},
						ID:   "children-info-last-name",
						Filter: &Filter{
							Type:      "string",
							MinLength: 1,
						},
					},
					{
						Path: []string{"$.vc.credentialSubject.children[*].age", "$.credentialSubject.children[*].age"},
						ID:   "children-info-age",
						Filter: &Filter{
							Type:      "number",
							MinLength: 1,
						},
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	definition, err := builder.Build()
	assert.NoError(t, err)
	println(util.PrettyJSON(definition))
}
