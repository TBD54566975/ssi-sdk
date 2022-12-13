package schema

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/jarcoal/httpmock"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
)

func TestCachingLoader(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	nameSchemaURI := "https://tbd.test/name-schema.json"
	httpmock.RegisterResponder("GET", nameSchemaURI,
		httpmock.NewStringResponder(200, getNameSchema()))

	emailSchemaURI := "https://tbd.test/email-schema.json"
	httpmock.RegisterResponder("GET", emailSchemaURI,
		httpmock.NewStringResponder(200, getEmailSchema()))

	// first load a schema that's not cached
	schema, err := jsonschema.Compile(nameSchemaURI)
	assert.NoError(t, err)
	assert.NotEmpty(t, schema)

	jsonInterface, err := util.ToJSONInterface(`{"firstName": "Sat", "lastName": "Toshi", "email": {"emailAddress": "st@tbd.com"}}`)
	assert.NoError(t, err)
	err = schema.Validate(jsonInterface)
	assert.NoError(t, err)

	// validate that there were network calls
	assert.Equal(t, 2, len(httpmock.GetCallCountInfo()))

	// now cache the schemas
	cl := NewCachingLoader()
	assert.NotEmpty(t, cl)
	err = cl.AddCachedSchema(nameSchemaURI, getNameSchema())
	assert.NoError(t, err)
	err = cl.AddCachedSchema(emailSchemaURI, getEmailSchema())
	assert.NoError(t, err)

	// load the schema, which should use the cache
	schema, err = jsonschema.Compile(nameSchemaURI)
	assert.NoError(t, err)
	assert.NotEmpty(t, schema)

	jsonInterface, err = util.ToJSONInterface(`{"firstName": "Sat", "lastName": "Toshi", "email": {"emailAddress": "st@tbd.com"}}`)
	assert.NoError(t, err)
	err = schema.Validate(jsonInterface)
	assert.NoError(t, err)

	schema, err = jsonschema.Compile(emailSchemaURI)
	assert.NoError(t, err)
	assert.NotEmpty(t, schema)

	jsonInterface, err = util.ToJSONInterface(`{"emailAddress": "st@tbd.com"}`)
	assert.NoError(t, err)
	err = schema.Validate(jsonInterface)
	assert.NoError(t, err)

	// assert no new network calls have been made
	assert.Equal(t, 2, len(httpmock.GetCallCountInfo()))
}

func TestCachingLoaderAllLocal(t *testing.T) {
	cl := NewCachingLoader()
	assert.NotEmpty(t, cl)

	localSchemas, err := GetAllLocalSchemas()
	assert.NoError(t, err)
	assert.NotEmpty(t, localSchemas)

	err = cl.AddCachedSchemas(localSchemas)
	assert.NoError(t, err)

	names, err := cl.GetCachedSchemas()
	assert.NoError(t, err)
	assert.NotEmpty(t, names)
}

func getNameSchema() string {
	return `{
  "$id": "https://tbd.test/name-schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Name",
  "description": "A human name.",
  "required": [ "firstName", "lastName" ],
  "type": "object",
  "properties": {
    "firstName": {
      "type": "string"
    },
    "lastName": {
      "type": "string"
    },
	"email": {
	  "$ref": "https://tbd.test/email-schema.json"    
	}
  }
}`
}

func getEmailSchema() string {
	return `{
  "$id": "https://tbd.test/email-schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Email",
  "description": "An email.",
  "required": [ "emailAddress" ],
  "type": "object",
  "properties": {
    "emailAddress": {
      "type": "string"
    }
  }
}`
}
