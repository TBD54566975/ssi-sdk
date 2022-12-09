package schema

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"

	vc "github.com/TBD54566975/ssi-sdk/credential"
)

const (
	vcJSONTestVector1           string = "vc-json-schema-example-1.json"
	vcJSONCredentialTestVector1 string = "vc-with-schema-example-11.json"
)

var (
	//go:embed testdata
	testVectors       embed.FS
	vcJSONTestVectors = []string{vcJSONTestVector1}
)

func TestIsValidCredentialSchema(t *testing.T) {
	for _, tv := range vcJSONTestVectors {
		schema, err := getTestVector(tv)
		assert.NoError(t, err)
		assert.NoError(t, IsValidCredentialSchema(schema))
	}
}

func TestCrap(t *testing.T) {
	s := `{
  "type": "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json",
  "version": "1.0",
  "id": "5b39bd5e-ed61-4ff5-bb02-471d89a3a3b6",
  "name": "license schema",
  "author": "did:key:z6MkhQnAnj6gVJDBSi8XJwSGufT7xR3WRL1PE7Zprvhjr3TL",
  "authored": "2022-12-09T10:44:28-08:00",
  "schema": {
    "$id": "5b39bd5e-ed61-4ff5-bb02-471d89a3a3b6",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": true,
    "description": "schema for license schema",
    "properties": {
      "licenseType": {
        "type": "string"
      }
    },
    "type": "object"
  }
}`
	err := IsValidCredentialSchema(s)
	assert.NoError(t, err)
}

func TestIsCredentialValidForSchema(t *testing.T) {
	// Load VC
	credential, err := getTestVector(vcJSONCredentialTestVector1)
	assert.NoError(t, err)
	var cred vc.VerifiableCredential
	err = json.Unmarshal([]byte(credential), &cred)
	assert.NoError(t, err)

	// Load vcJSONSchema
	vcJSONSchemaString, err := getTestVector(vcJSONTestVector1)
	assert.NoError(t, err)

	vcJSONSchema, err := StringToVCJSONCredentialSchema(vcJSONSchemaString)
	assert.NoError(t, err)
	assert.NotEmpty(t, vcJSONSchema)

	// Validate credential against vcJSONSchema
	err = IsCredentialValidForVCJSONSchema(cred, *vcJSONSchema)
	assert.NoError(t, err)

	// make sure the cred was not modified
	var credCopy vc.VerifiableCredential
	err = json.Unmarshal([]byte(credential), &credCopy)
	assert.NoError(t, err)
	assert.Equal(t, credCopy, cred)
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
