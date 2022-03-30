package rendering

import (
	"github.com/TBD54566975/did-sdk/schema"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Get all schemas, make sure they're valid
func TestWalletRenderingSchemas(t *testing.T) {
	dmoSchema, err := getKnownSchema(displayMappingObjectSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, dmoSchema)
	err = schema.IsValidJSONSchema(dmoSchema)
	assert.NoError(t, err)

	esSchema, err := getKnownSchema(entityStylesSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, esSchema)
	err = schema.IsValidJSONSchema(esSchema)
	assert.NoError(t, err)

	ldmoSchema, err := getKnownSchema(labeledDisplayMappingObjectSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, ldmoSchema)
	err = schema.IsValidJSONSchema(ldmoSchema)
	assert.NoError(t, err)
}
