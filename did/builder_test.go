package did

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Exercise all builder methods
func TestDIDDocumentBuilder(t *testing.T) {
	builder := NewDIDDocumentBuilder()
	_, err := builder.Build()
	assert.Error(t, err)
	notReadyErr := "did not ready to be built"
	assert.Contains(t, err.Error(), notReadyErr)

	assert.False(t, builder.IsEmpty())

	// default context should be set
	assert.NotEmpty(t, builder.Context)

	// set context of a bad type
	err = builder.AddContext(4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed context")

	// correct context
	err = builder.AddContext("https://w3id.org/did/v1")
	assert.NoError(t, err)

	// there is a default id
	assert.NotEmpty(t, builder.ID)

	// set id
	id := "test-id"
	err = builder.SetID(id)
	assert.NoError(t, err)

	// set also known as
	err = builder.SetAlsoKnownAs("aka")
	assert.NoError(t, err)

	// TODO: Fix test methods
	// set controller
	err = builder.SetController("controller")
	assert.NoError(t, err)

	// valid type as a []string
	err = builder.AddAuthentication([]string{"TestType"})
	assert.NoError(t, err)

	// set issuer as a string
	err = builder.AddAssertionMethod("issuer")
	assert.NoError(t, err)

	// set issuer as a string
	err = builder.AddKeyAgreement("issuer")
	assert.NoError(t, err)

	err = builder.AddCapabilityInvocation("issuer")
	assert.NoError(t, err)

	err = builder.AddCapabilityDelgation("issuer")
	assert.NoError(t, err)

	err = builder.AddService(Service{})
	assert.NoError(t, err)
	// build it and verify some values
	cred, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, cred)

	assert.Equal(t, id, cred.ID)
}
