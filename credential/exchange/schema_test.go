package exchange

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/schema"
)

// Get all schemas, make sure they're valid
func TestPresentationExchangeSchemas(t *testing.T) {
	pdSchema, err := schema.LoadSchema(schema.PresentationDefinitionSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, pdSchema)
	err = schema.IsValidJSONSchema(pdSchema)
	assert.NoError(t, err)

	fdSchema, err := schema.LoadSchema(schema.PresentationClaimFormatDesignationsSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, fdSchema)
	err = schema.IsValidJSONSchema(fdSchema)
	assert.NoError(t, err)

	srSchema, err := schema.LoadSchema(schema.SubmissionRequirementsSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, srSchema)
	err = schema.IsValidJSONSchema(srSchema)
	assert.NoError(t, err)
}
