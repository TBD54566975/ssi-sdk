package exchange

import (
	"github.com/TBD54566975/did-sdk/schema"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Get all schemas, make sure they're valid
func TestPresentationExchangeSchemas(t *testing.T) {
	pdSchema, err := getKnownSchema(presentationDefinitionSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, pdSchema)
	err = schema.IsValidJSONSchema(pdSchema)
	assert.NoError(t, err)

	fdSchema, err := getKnownSchema(formatDeclarationSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, fdSchema)
	err = schema.IsValidJSONSchema(fdSchema)
	assert.NoError(t, err)

	srSchema, err := getKnownSchema(submissionRequirementsSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, srSchema)
	err = schema.IsValidJSONSchema(srSchema)
	assert.NoError(t, err)
}
