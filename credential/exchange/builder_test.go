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

}
