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

	httpmock.RegisterResponder("GET", "https://tbd.test/name-schema.json",
		httpmock.NewStringResponder(200, getNameSchema()))

	httpmock.RegisterResponder("GET", "https://tbd.test/email-schema.json",
		httpmock.NewStringResponder(200, getEmailSchema()))

	// first load a schema that's not cached
	schema, err := jsonschema.Compile("https://tbd.test/name-schema.json")
	assert.NoError(t, err)
	assert.NotEmpty(t, schema)

	jsonInterface, err := util.ToJSONInterface(`{"firstName": "Sat", "lastName": "Toshi", "email": {"emailAddress": "st@tbd.com"}}`)
	assert.NoError(t, err)
	err = schema.Validate(jsonInterface)
	assert.NoError(t, err)

	// validate that there were network calls
	assert.Equal(t, 2, len(httpmock.GetCallCountInfo()))
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
