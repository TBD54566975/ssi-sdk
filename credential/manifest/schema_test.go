package manifest

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/schema"
)

// Get all schemas, make sure they're valid
func TestCredentialManifestSchemas(t *testing.T) {
	cmSchema, err := getKnownSchema(credentialManifestSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, cmSchema)
	err = schema.IsValidJSONSchema(cmSchema)
	assert.NoError(t, err)

	caSchema, err := getKnownSchema(credentialApplicationSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, caSchema)
	err = schema.IsValidJSONSchema(caSchema)
	assert.NoError(t, err)

	cfSchema, err := getKnownSchema(credentialResponseSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, cfSchema)
	err = schema.IsValidJSONSchema(cfSchema)
	assert.NoError(t, err)

	odSchema, err := getKnownSchema(outputDescriptorsSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, odSchema)
	err = schema.IsValidJSONSchema(odSchema)
	assert.NoError(t, err)
}
