package verification

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/stretchr/testify/assert"
)

func TestVerifier(t *testing.T) {
	t.Run("Test Basic Verifier", func(tt *testing.T) {
		// empty verifier
		_, err := NewCredentialVerifier(nil)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "no verifiers provided")

		// no op verifier
		noop := Verifier{
			ID:         "noop",
			VerifyFunc: NoOpVerifier,
		}
		verifier, err := NewCredentialVerifier([]Verifier{noop})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifier)

		// verify
		err = verifier.VerifyCredential(credential.VerifiableCredential{})
		assert.NoError(tt, err)

		sampleCredential := getSampleCredential()

		err = verifier.VerifyCredential(sampleCredential)
		assert.NoError(t, err)
	})

	t.Run("Expiry Verifier", func(tt *testing.T) {
		// expiry verifier
		expiry := Verifier{
			ID:         "expiration date checking",
			VerifyFunc: VerifyExpiry,
		}
		verifier, err := NewCredentialVerifier([]Verifier{expiry})
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifier)

		sampleCredential := getSampleCredential()

		err = verifier.VerifyCredential(sampleCredential)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential has expired as of 2021-01-01 00:00:00 +0000 UTC")
	})

	t.Run("Schema Verifier", func(tt *testing.T) {
		// set up schema verifier
		schema := Verifier{
			ID:         "JSON Schema checking",
			VerifyFunc: VerifyJSONSchema,
		}

		verifier, err := NewCredentialVerifier([]Verifier{schema})
		assert.NoError(t, err)
		assert.NotEmpty(t, verifier)

		sampleCredential := getSampleCredential()

		// verify cred with no schema, no schema passed in
		err = verifier.VerifyCredential(sampleCredential)
		assert.NoError(t, err)

		// verify cred with no schema, schema passed in
		badSchema := `{"bad":"schema"}`
		err = verifier.VerifyCredential(sampleCredential, WithSchema(badSchema))
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "credential does not have a credentialSchema property")

		// verify cred with schema, no schema passed in
		sampleCredential.CredentialSchema = &credential.CredentialSchema{
			ID:   "did:example:MDP8AsFhHzhwUvGNuYkX7T;id=06e126d1-fa44-4882-a243-1e326fbe21db;version=1.0",
			Type: "JsonSchemaValidator2018",
		}
		err = verifier.VerifyCredential(sampleCredential)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "no schema provided")

		// verify cred with schema, schema passed in, cred with bad data
		knownSchema := getVCJSONSchema()
		err = verifier.VerifyCredential(sampleCredential, WithSchema(knownSchema))
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "missing properties: 'emailAddress'")

		// verify cred with schema, schema passed in, cred with good data
		sampleCredential.CredentialSubject = map[string]any{
			"id":           "test-vc-id",
			"emailAddress": "grandma@aol.com",
		}
		err = verifier.VerifyCredential(sampleCredential, WithSchema(knownSchema))
		assert.NoError(tt, err)
	})
}

func NoOpVerifier(_ credential.VerifiableCredential, _ ...Option) error {
	return nil
}

func getSampleCredential() credential.VerifiableCredential {
	return credential.VerifiableCredential{
		Context: []any{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		ID:             "test-verifiable-credential",
		Type:           []string{"VerifiableCredential"},
		Issuer:         "test-issuer",
		ExpirationDate: "2021-01-01T00:00:00Z",
		IssuanceDate:   "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id":      "test-vc-id",
			"company": "Block",
			"website": "https://block.xyz",
		},
	}
}

func getVCJSONSchema() string {
	return `{
		"type": "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json",
		"version": "1.0",
		"id": "did:example:MDP8AsFhHzhwUvGNuYkX7T;id=06e126d1-fa44-4882-a243-1e326fbe21db;version=1.0",
		"name": "Email",
		"author": "did:example:MDP8AsFhHzhwUvGNuYkX7T",
		"authored": "2021-01-01T00:00:00+00:00",
		"schema": {
			"$id": "email-schema-1.0",
			"$schema": "https://json-schema.org/draft/2019-09/schema",
			"description": "Email",
			"type": "object",
			"properties": {
			"emailAddress": {
				"type": "string",
					"format": "email"
			}
		},
		"required": ["emailAddress"],
		"additionalProperties": false
		}
	}`
}
