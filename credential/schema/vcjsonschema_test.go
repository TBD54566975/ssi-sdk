package schema

import (
	"context"
	"embed"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

const (
	jsonSchemaCredential1           string = "jsonschema-credential-1.json"
	jsonSchemaSchema1               string = "jsonschema-schema-1.json"
	jsonSchemaCredentialCredential1 string = "jsonschemacredential-credential-1.json"
	jsonSchemaCredentialSchema1     string = "jsonschemacredential-schema-1.json"
)

var (
	//go:embed testdata
	testVectors embed.FS
)

func TestValidateCredentialAgainstSchema_JsonSchema(t *testing.T) {
	t.Run("validate credential against JsonSchema", func(t *testing.T) {
		cred, err := getTestVector(jsonSchemaCredential1)
		assert.NoError(t, err)

		var vc credential.VerifiableCredential
		err = json.Unmarshal([]byte(cred), &vc)
		assert.NoError(t, err)

		err = ValidateCredentialAgainstSchema(&localAccess{}, vc)
		assert.NoError(t, err)
	})

	t.Run("ID - The value MUST be a URL that identifies the schema associated with the verifiable credential.", func(t *testing.T) {

	})

	t.Run("the type property MUST be JsonSchema", func(t *testing.T) {

	})

	t.Run("the $id property MUST be present and its value MUST represent a valid URI", func(t *testing.T) {

	})

	t.Run("the $schema property MUST be present", func(t *testing.T) {

	})
}

func TestValidateCredentialAgainstSchema_JsonSchemaCredential(t *testing.T) {
	t.Run("validate credential against JsonSchemaCredential", func(t *testing.T) {
		cred, err := getTestVector(jsonSchemaCredentialCredential1)
		assert.NoError(t, err)

		var vc credential.VerifiableCredential
		err = json.Unmarshal([]byte(cred), &vc)
		assert.NoError(t, err)

		err = ValidateCredentialAgainstSchema(&localAccess{}, vc)
		assert.NoError(t, err)
	})

	t.Run("ID - The value MUST be a URL that identifies the schema associated with the verifiable credential.", func(t *testing.T) {

	})

	t.Run("the type property MUST be JsonSchemaCredential", func(t *testing.T) {

	})

	t.Run("the credentialSubject property MUST contain two properties: type - the value of which MUST be "+
		"JsonSchema; jsonSchema - an object which contains a valid JSON Schema", func(t *testing.T) {
	})

	t.Run("the $id property MUST be present and its value MUST represent a valid URI", func(t *testing.T) {

	})

	t.Run("the $schema property MUST be present", func(t *testing.T) {

	})
}

type localAccess struct{}

func (localAccess) GetVCJSONSchema(_ context.Context, _ VCJSONSchemaType, id string) (VCJSONSchema, error) {
	var schema string
	var s VCJSONSchema
	var err error
	switch id {
	case "https://example.com/schemas/email.json":
		schema, err = getTestVector(jsonSchemaSchema1)
		if err != nil {
			return nil, err
		}
	case "https://example.com/credentials/3734":
		schemaCred, err := getTestVector(jsonSchemaCredentialSchema1)
		if err != nil {
			return nil, err
		}
		schema = schemaCred
	}
	if err = json.Unmarshal([]byte(schema), &s); err != nil {
		return nil, err
	}
	return s, nil
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
