package manifest

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/schema"
)

// TestMain is used to set up schema caching in order to load all schemas locally
func TestMain(m *testing.M) {
	localSchemas, err := schema.GetAllLocalSchemas()
	if err != nil {
		os.Exit(1)
	}
	cl := schema.NewCachingLoader()
	if err = cl.AddCachedSchemas(localSchemas); err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// Get all schemas, make sure they're valid
func TestCredentialManifestSchemas(t *testing.T) {
	cmSchema, err := schema.LoadSchema(schema.CredentialManifestSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, cmSchema)
	err = schema.IsValidJSONSchema(cmSchema)
	assert.NoError(t, err)

	caSchema, err := schema.LoadSchema(schema.CredentialApplicationSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, caSchema)
	err = schema.IsValidJSONSchema(caSchema)
	assert.NoError(t, err)

	cfSchema, err := schema.LoadSchema(schema.CredentialResponseSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, cfSchema)
	err = schema.IsValidJSONSchema(cfSchema)
	assert.NoError(t, err)

	odSchema, err := schema.LoadSchema(schema.OutputDescriptorsSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, odSchema)
	err = schema.IsValidJSONSchema(odSchema)
	assert.NoError(t, err)
}
