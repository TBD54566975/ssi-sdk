package manifest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/schema"
)

// Get all schemas, make sure they're valid
func TestCredentialManifestSchemas(t *testing.T) {
	cmSchema, err := schema.GetKnownSchema(credentialManifestSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, cmSchema)
	err = schema.IsValidJSONSchema(cmSchema)
	assert.NoError(t, err)

	caSchema, err := schema.GetKnownSchema(credentialApplicationSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, caSchema)
	err = schema.IsValidJSONSchema(caSchema)
	assert.NoError(t, err)

	cfSchema, err := schema.GetKnownSchema(credentialResponseSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, cfSchema)
	err = schema.IsValidJSONSchema(cfSchema)
	assert.NoError(t, err)

	odSchema, err := schema.GetKnownSchema(outputDescriptorsSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, odSchema)
	err = schema.IsValidJSONSchema(odSchema)
	assert.NoError(t, err)
}
