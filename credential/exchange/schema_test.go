package exchange

import (
	"os"
	"testing"

	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/stretchr/testify/assert"
)

// TestMain is used to set up schema caching in order to load all schemas locally
func TestMain(m *testing.M) {
	localSchemas, err := schema.GetAllLocalSchemas()
	if err != nil {
		os.Exit(1)
	}
	loader, err := schema.NewCachingLoader(localSchemas)
	if err != nil {
		os.Exit(1)
	}
	loader.EnableHTTPCache()
	os.Exit(m.Run())
}

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
