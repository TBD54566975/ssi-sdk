package schema

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/h2non/gock.v1"
)

func TestRemoteAccess(t *testing.T) {
	remoteAccess := NewRemoteAccess(nil)
	schema, err := getTestVector(jsonSchema2023Schema1)
	require.NoError(t, err)

	schemaCred, err := getTestVector(credentialSchema2023Schema1)
	require.NoError(t, err)

	t.Run("access JsonSchema2023", func(t *testing.T) {
		gock.New("https://example.com/schemas").
			Get("/email.json").
			Reply(200).BodyString(schema)
		defer gock.Off()

		jsonSchema, err := remoteAccess.GetVCJSONSchema(context.Background(), JSONSchema2023Type, "https://example.com/schemas/email.json")
		assert.NoError(t, err)
		assert.JSONEq(t, schema, jsonSchema.String())
	})

	t.Run("validate credential against JsonSchema2023", func(t *testing.T) {
		gock.New("https://example.com/schemas").
			Get("/email.json").
			Reply(200).BodyString(schema)
		defer gock.Off()

		cred, err := getTestVector(jsonSchema2023Credential1)
		assert.NoError(t, err)

		var vc credential.VerifiableCredential
		err = json.Unmarshal([]byte(cred), &vc)
		assert.NoError(t, err)

		err = ValidateCredentialAgainstSchema(remoteAccess, vc)
		assert.NoError(t, err)
	})

	t.Run("access CredentialSchema2023", func(t *testing.T) {
		gock.New("https://example.com/credentials").
			Get("/3734").
			Reply(200).BodyString(schemaCred)
		defer gock.Off()

		jsonSchema, err := remoteAccess.GetVCJSONSchema(context.Background(), JSONSchema2023Type, "https://example.com/credentials/3734")
		assert.NoError(t, err)
		assert.JSONEq(t, schemaCred, jsonSchema.String())
	})

	t.Run("validate credential against CredentialSchema2023", func(t *testing.T) {
		gock.New("https://example.com/credentials").
			Get("/3734").
			Reply(200).BodyString(schemaCred)
		defer gock.Off()

		cred, err := getTestVector(credentialSchema2023Credential1)
		assert.NoError(t, err)

		var vc credential.VerifiableCredential
		err = json.Unmarshal([]byte(cred), &vc)
		assert.NoError(t, err)

		err = ValidateCredentialAgainstSchema(remoteAccess, vc)
		assert.NoError(t, err)
	})
}
