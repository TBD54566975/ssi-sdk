package schema

import (
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

	t.Run("test validate credential against JsonSchema2023", func(t *testing.T) {
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

	t.Run("test validate credential against CredentialSchema2023", func(t *testing.T) {
		gock.New("https://example.com/schemas").
			Get("/email-credential-schema.json").
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
