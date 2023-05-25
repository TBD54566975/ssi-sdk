package schema

import (
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

func TestVCJSONSchema(t *testing.T) {
	testSchema := `{
  "$id": "https://example.com/schemas/email.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "name": "EmailCredential",
  "description": "EmailCredential using JsonSchema2023",
  "type": "object",
  "properties": {
    "credentialSubject": {
      "type": "object",
      "properties": {
        "emailAddress": {
          "type": "string",
          "format": "email"
        }
      },
      "required": [
        "emailAddress"
      ]
    }
  }
}`

	var vcSchema JSONSchema
	err := json.Unmarshal([]byte(testSchema), &vcSchema)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcSchema)

	assert.Equal(t, "https://example.com/schemas/email.json", vcSchema.ID())
	assert.Equal(t, "https://json-schema.org/draft/2020-12/schema", vcSchema.Schema())
	assert.Equal(t, "EmailCredential", vcSchema.Name())
	assert.Equal(t, "EmailCredential using JsonSchema2023", vcSchema.Description())
}
