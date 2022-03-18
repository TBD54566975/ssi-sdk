package credential

import (
	"github.com/TBD54566975/did-sdk/schema"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Get all schemas, make sure they're valid
func TestCredentialManifestSchemas(t *testing.T) {
	cmSchema, err := getKnownSchema(credentialManifestSchema)
	assert.NoError(t, err)
	err = schema.IsValidJSONSchema(cmSchema)
	assert.NoError(t, err)

	caSchema, err := getKnownSchema(credentialApplicationSchema)
	assert.NoError(t, err)
	err = schema.IsValidJSONSchema(caSchema)
	assert.NoError(t, err)

	cfSchema, err := getKnownSchema(credentialFulfillmentSchema)
	assert.NoError(t, err)
	err = schema.IsValidJSONSchema(cfSchema)
	assert.NoError(t, err)

	odSchema, err := getKnownSchema(outputDescriptorsSchema)
	assert.NoError(t, err)
	err = schema.IsValidJSONSchema(odSchema)
	assert.NoError(t, err)
}

// Get all schemas, make sure they're valid
func TestPresentationExchangeSchemas(t *testing.T) {
	pdSchema, err := getKnownSchema(presentationDefinitionSchema)
	assert.NoError(t, err)
	err = schema.IsValidJSONSchema(pdSchema)
	assert.NoError(t, err)

	fdSchema, err := getKnownSchema(formatDeclarationSchema)
	assert.NoError(t, err)
	err = schema.IsValidJSONSchema(fdSchema)
	assert.NoError(t, err)

	srSchema, err := getKnownSchema(submissionRequirementsSchema)
	assert.NoError(t, err)
	err = schema.IsValidJSONSchema(srSchema)
	assert.NoError(t, err)
}
