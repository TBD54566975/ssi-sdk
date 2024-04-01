package schema

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/jarcoal/httpmock"
	"github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/assert"
)

func TestCachingLoader(t *testing.T) {
	t.Run("test load from remote resource without caching", func(t *testing.T) {
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
	})

	t.Run("test load from remote resource with caching", func(t *testing.T) {
		nameSchemaURI := "https://tbd.test/name-schema.json"
		emailSchemaURI := "https://tbd.test/email-schema.json"

		schemaCache := map[string]string{
			nameSchemaURI:  getNameSchema(),
			emailSchemaURI: getEmailSchema(),
		}
		cl, err := NewCachingLoader(schemaCache)
		assert.NotEmpty(t, cl)
		assert.NoError(t, err)
		cl.EnableHTTPCache()

		// load the schema, which should use the cache
		schema, err := jsonschema.Compile(nameSchemaURI)
		assert.NoError(t, err)
		assert.NotEmpty(t, schema)

		jsonInterface, err := util.ToJSONInterface(`{"firstName": "Sat", "lastName": "Toshi", "email": {"emailAddress": "st@tbd.com"}}`)
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
	})
}

func TestCachingLoaderAllLocal(t *testing.T) {
	localSchemas, err := GetAllLocalSchemas()
	assert.NoError(t, err)
	assert.NotEmpty(t, localSchemas)
	cl, err := NewCachingLoader(localSchemas)
	assert.NotEmpty(t, cl)
	assert.NoError(t, err)

	cl.EnableHTTPCache()

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
