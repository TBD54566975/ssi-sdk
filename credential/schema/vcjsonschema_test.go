package schema

import (
	"context"
	"embed"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	jsonSchema2023Credential1       string = "jsonschema2023-credential-1.json"
	jsonSchema2023Schema1           string = "jsonschema2023-schema-1.json"
	credentialSchema2023Credential1 string = "credentialschema2023-credential-1.json"
	credentialSchema2023Schema1     string = "credentialschema2023-schema-1.json"
)

var (
	//go:embed testdata
	testVectors embed.FS
)

func TestValidateCredentialAgainstSchema(t *testing.T) {
	t.Run("validate credential against JsonSchema2023", func(t *testing.T) {
		cred, err := getTestVector(jsonSchema2023Credential1)
		assert.NoError(t, err)

		var vc credential.VerifiableCredential
		err = json.Unmarshal([]byte(cred), &vc)
		assert.NoError(t, err)

		err = ValidateCredentialAgainstSchema(&localAccess{}, vc)
		assert.NoError(t, err)
	})

	t.Run("validate credential against CredentialSchema2023", func(t *testing.T) {
		cred, err := getTestVector(credentialSchema2023Credential1)
		assert.NoError(t, err)

		var vc credential.VerifiableCredential
		err = json.Unmarshal([]byte(cred), &vc)
		assert.NoError(t, err)

		err = ValidateCredentialAgainstSchema(&localAccess{}, vc)
		assert.NoError(t, err)
	})
}

type localAccess struct{}

func (localAccess) GetVCJSONSchema(_ context.Context, _ VCJSONSchemaType, id string) (JSONSchema, error) {
	var schema string
	var s JSONSchema
	var err error
	switch id {
	case "https://example.com/schemas/email.json":
		schema, err = getTestVector(jsonSchema2023Schema1)
		if err != nil {
			return nil, err
		}
	case "https://example.com/credentials/3734":
		schemaCred, err := getTestVector(credentialSchema2023Schema1)
		if err != nil {
			return nil, err
		}
		var cred credential.VerifiableCredential
		if err = json.Unmarshal([]byte(schemaCred), &cred); err != nil {
			return nil, err
		}
		credSubjectBytes, err := json.Marshal(cred.CredentialSubject)
		if err != nil {
			return nil, errors.Wrap(err, "error marshalling credential subject")
		}
		schema = string(credSubjectBytes)
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
