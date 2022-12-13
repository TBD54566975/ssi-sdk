package rendering

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
func TestWalletRenderingSchemas(t *testing.T) {
	dmoSchema, err := schema.LoadSchema(schema.DisplayMappingObjectSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, dmoSchema)
	err = schema.IsValidJSONSchema(dmoSchema)
	assert.NoError(t, err)

	esSchema, err := schema.LoadSchema(schema.EntityStylesSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, esSchema)
	err = schema.IsValidJSONSchema(esSchema)
	assert.NoError(t, err)

	ldmoSchema, err := schema.LoadSchema(schema.LabeledDisplayMappingObjectSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, ldmoSchema)
	err = schema.IsValidJSONSchema(ldmoSchema)
	assert.NoError(t, err)
}
