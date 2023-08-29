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

// test vectors from the spec
func TestValidateCredentialAgainstSchema(t *testing.T) {
	t.Run("validate credential against JsonSchema", func(t *testing.T) {
		cred, err := getTestVector(jsonSchemaCredential1)
		assert.NoError(t, err)

		var vc credential.VerifiableCredential
		err = json.Unmarshal([]byte(cred), &vc)
		assert.NoError(t, err)

		err = ValidateCredentialAgainstSchema(&localAccess{}, vc)
		assert.NoError(t, err)
	})

	t.Run("validate credential against JsonSchemaCredential", func(t *testing.T) {
		cred, err := getTestVector(jsonSchemaCredentialCredential1)
		assert.NoError(t, err)

		var vc credential.VerifiableCredential
		err = json.Unmarshal([]byte(cred), &vc)
		assert.NoError(t, err)

		err = ValidateCredentialAgainstSchema(&localAccess{}, vc)
		assert.NoError(t, err)
	})
}

func TestIsCredentialValidForJSONSchema_JsonSchema(t *testing.T) {
	t.Run("ID - The value MUST be a URL that identifies the schema associated with the verifiable credential.", func(t *testing.T) {
		t.Run("valid id", func(t *testing.T) {
			cred := getTestJSONSchemaCredential()
			schema := getTestJSONSchemaSchema()
			assert.Equal(t, cred.CredentialSchema.ID, schema["$id"])
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.NoError(t, err)
		})

		t.Run("mismatched id", func(t *testing.T) {
			// modify the ID
			cred := getTestJSONSchemaCredential()
			schema := getTestJSONSchemaSchema()
			schema["$id"] = "https://example.com/schemas/email2.json"
			assert.NotEqual(t, cred.CredentialSchema.ID, schema["$id"])
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema ID<https://example.com/schemas/email.json> does not match schema ID<https://example.com/schemas/email2.json>")
		})
	})

	t.Run("the type property MUST be JsonSchema", func(t *testing.T) {
		t.Run("valid type", func(t *testing.T) {
			cred := getTestJSONSchemaCredential()
			schema := getTestJSONSchemaSchema()
			assert.Equal(t, cred.CredentialSchema.Type, JSONSchemaType.String())
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.NoError(t, err)
		})

		t.Run("valid but mismatched type", func(t *testing.T) {
			cred := getTestJSONSchemaCredential()
			cred.CredentialSchema.Type = JSONSchemaCredentialType.String()
			schema := getTestJSONSchemaSchema()
			assert.NotEqual(t, cred.CredentialSchema.Type, JSONSchemaType.String())
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema type<JsonSchemaCredential> does not match schema type<JsonSchema>")
		})

		t.Run("invalid type", func(t *testing.T) {
			cred := getTestJSONSchemaCredential()
			cred.CredentialSchema.Type = "bad"
			schema := getTestJSONSchemaSchema()
			assert.NotEqual(t, cred.CredentialSchema.Type, JSONSchemaType.String())
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema type<bad> is not supported")
		})
	})

	t.Run("the $id property MUST be present and its value MUST represent a valid URI", func(t *testing.T) {
		t.Run("$id is a valid URI", func(t *testing.T) {
			cred := getTestJSONSchemaCredential()
			schema := getTestJSONSchemaSchema()
			assert.True(t, isValidURI(schema["$id"].(string)))
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.NoError(t, err)
		})

		t.Run("$id is a URN which is still a valid URI", func(t *testing.T) {
			cred := getTestJSONSchemaCredential()
			schema := getTestJSONSchemaSchema()

			urnUUID := "urn:uuid:1234"
			cred.CredentialSchema.ID = urnUUID
			schema["$id"] = urnUUID

			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.NoError(t, err)
		})

		t.Run("$id is not a valid URI", func(t *testing.T) {
			cred := getTestJSONSchemaCredential()
			schema := getTestJSONSchemaSchema()

			invalidURI := "bad"
			cred.CredentialSchema.ID = invalidURI
			schema["$id"] = invalidURI

			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "not a valid URI")
		})
	})

	t.Run("the $schema property MUST be present", func(t *testing.T) {
		t.Run("schema property is present and not empty", func(t *testing.T) {
			cred := getTestJSONSchemaCredential()
			schema := getTestJSONSchemaSchema()
			assert.NotEmpty(t, schema["$schema"])
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.NoError(t, err)
		})

		t.Run("schema property is not present", func(t *testing.T) {
			cred := getTestJSONSchemaCredential()
			schema := getTestJSONSchemaSchema()
			delete(schema, "$schema")
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema does not contain a `$schema` property")
		})
	})
}

func TestIsCredentialValidForJSONSchema_JsonSchemaCredential(t *testing.T) {
	t.Run("ID - The value MUST be a URL that identifies the schema associated with the verifiable credential.", func(t *testing.T) {
		t.Run("valid id", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			assert.Equal(t, cred.CredentialSchema.ID, schema["id"])
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.NoError(t, err)
		})

		t.Run("mismatched id", func(t *testing.T) {
			// modify the ID
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			schema["id"] = "bad"
			assert.NotEqual(t, cred.CredentialSchema.ID, schema["id"])
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema ID<https://example.com/credentials/3734> does not match schema ID<bad>")
		})
	})

	t.Run("the type property MUST be JsonSchemaCredential", func(t *testing.T) {
		t.Run("valid type", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			assert.Equal(t, cred.CredentialSchema.Type, JSONSchemaCredentialType.String())
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.NoError(t, err)
		})

		t.Run("valid but mismatched type", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			cred.CredentialSchema.Type = JSONSchemaType.String()
			schema := getTestVCJSONSchemaSchema()
			assert.NotEqual(t, cred.CredentialSchema.Type, JSONSchemaCredentialType.String())
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema type<JsonSchema> does not match schema type<JsonSchemaCredential>")
		})

		t.Run("invalid type", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			cred.CredentialSchema.Type = "bad"
			schema := getTestVCJSONSchemaSchema()
			assert.NotEqual(t, cred.CredentialSchema.Type, JSONSchemaCredentialType.String())
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema type<bad> is not supported")
		})
	})

	t.Run("the credentialSubject property MUST contain two properties: type - the value of which MUST be "+
		"JsonSchema; jsonSchema - an object which contains a valid JSON Schema", func(t *testing.T) {
		t.Run("contains both properties which are valid", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			credSubject := schema["credentialSubject"].(map[string]any)
			assert.Equal(t, credSubject["type"], JSONSchemaType.String())
			assert.NotEmpty(t, credSubject["jsonSchema"])
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.NoError(t, err)
		})

		t.Run("missing type property", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			credSubject := schema["credentialSubject"].(map[string]any)
			delete(credSubject, "type")
			schema["credentialSubject"] = credSubject
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema's credential subject does not contain a `type`")
		})

		t.Run("missing jsonSchema property", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			credSubject := schema["credentialSubject"].(map[string]any)
			delete(credSubject, "jsonSchema")
			schema["credentialSubject"] = credSubject
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema's credential subject does not contain a valid `jsonSchema`")
		})

		t.Run("jsonSchema property is not a valid json schema", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			credSubject := schema["credentialSubject"].(map[string]any)
			credSubject["jsonSchema"] = "bad"
			schema["credentialSubject"] = credSubject
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema's credential subject does not contain a valid `jsonSchema`")
		})
	})

	t.Run("2.2 The value of the credentialSchema property MUST always be set to [known json schema]", func(t *testing.T) {
		t.Run("valid credentialSchema", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.NoError(t, err)
		})

		t.Run("credentialSchema wrong id", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			schema["credentialSchema"] = map[string]any{
				"id":        "bad",
				"type":      JSONSchemaType,
				"digestSRI": JSONSchemaCredentialDigestSRI,
			}
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema's credential schema id<bad> does not match known id")
		})

		t.Run("credentialSchema wrong type", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			schema["credentialSchema"] = map[string]any{
				"id":        JSONSchemaCredentialSchemaID,
				"type":      "NotJsonSchema",
				"digestSRI": JSONSchemaCredentialDigestSRI,
			}
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema's credential schema type<NotJsonSchema> does not match known type<JsonSchema>")
		})

		t.Run("credentialSchema missing digestSRI", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			schema["credentialSchema"] = map[string]any{
				"id":   JSONSchemaCredentialSchemaID,
				"type": JSONSchemaType,
			}
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema's credential schema digest sri<> does not match known sri")
		})
	})

	t.Run("the $id property MUST be present and its value MUST represent a valid URI", func(t *testing.T) {
		t.Run("$id is a valid URI", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			schemaSubject := schema["credentialSubject"].(map[string]any)
			schemaSubjectSchema := schemaSubject["jsonSchema"].(map[string]any)
			assert.True(t, isValidURI(schemaSubjectSchema["$id"].(string)))
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.NoError(t, err)
		})

		t.Run("$id is not a valid URI", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()

			invalidURI := "bad"
			schemaSubject := schema["credentialSubject"].(map[string]any)
			schemaSubjectSchema := schemaSubject["jsonSchema"].(map[string]any)
			schemaSubjectSchema["$id"] = invalidURI
			schemaSubject["jsonSchema"] = schemaSubjectSchema
			schema["credentialSubject"] = schemaSubject

			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.ErrorContains(t, err, "not a valid URI")
		})
	})

	t.Run("the $schema property MUST be present", func(t *testing.T) {
		t.Run("schema property is present and not empty", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			schemaCredSubject := schema["credentialSubject"].(map[string]any)
			schemaCredSubjectSchema := schemaCredSubject["jsonSchema"].(map[string]any)
			assert.NotEmpty(t, schemaCredSubjectSchema["$schema"])
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.NoError(t, err)
		})

		t.Run("schema property is not present", func(t *testing.T) {
			cred := getTestVCJSONSchemaCredential()
			schema := getTestVCJSONSchemaSchema()
			schemaCredSubject := schema["credentialSubject"].(map[string]any)
			schemaCredSubjectSchema := schemaCredSubject["jsonSchema"].(map[string]any)
			delete(schemaCredSubjectSchema, "$schema")
			schemaCredSubject["jsonSchema"] = schemaCredSubjectSchema
			schema["credentialSubject"] = schemaCredSubject
			err := IsCredentialValidForJSONSchema(cred, schema, JSONSchemaCredentialType)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "credential schema does not contain a `$schema` property")
		})
	})
}

func getTestJSONSchemaCredential() credential.VerifiableCredential {
	return credential.VerifiableCredential{
		ID:     "https://example.com/credentials/3734",
		Issuer: " https://example.com/issuers/14",
		CredentialSubject: map[string]any{
			"id":           "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"emailAddress": "test@test.com",
		},
		CredentialSchema: &credential.CredentialSchema{
			ID:   "https://example.com/schemas/email.json",
			Type: "JsonSchema",
		},
	}
}

func getTestJSONSchemaSchema() VCJSONSchema {
	return VCJSONSchema{
		"$id":     "https://example.com/schemas/email.json",
		"$schema": "https://json-schema.org/draft-07/schema#",
		"title":   "Email address",
		"type":    "object",
		"properties": map[string]any{
			"credentialSubject": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"emailAddress": map[string]any{
						"type": "string",
					},
				},
				"required": []string{"emailAddress"},
			},
		},
		"required": []string{"credentialSubject"},
	}
}

func getTestVCJSONSchemaCredential() credential.VerifiableCredential {
	return credential.VerifiableCredential{
		ID:     "https://example.com/credentials/3734",
		Issuer: " https://example.com/issuers/14",
		CredentialSubject: map[string]any{
			"id":           "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"emailAddress": "test@test.com",
		},
		CredentialSchema: &credential.CredentialSchema{
			ID:   "https://example.com/credentials/3734",
			Type: "JsonSchemaCredential",
		},
	}
}

func getTestVCJSONSchemaSchema() VCJSONSchema {
	return VCJSONSchema{
		"id":           "https://example.com/credentials/3734",
		"issuer":       "https://example.com/issuers/14",
		"issuanceDate": "2010-01-01T19:23:24Z",
		"credentialSubject": map[string]any{
			"id":   "https://example.com/schemas/email-credential-schema.json",
			"type": "JsonSchema",
			"jsonSchema": map[string]any{
				"$id":     "https://example.com/schemas/email.json",
				"$schema": "https://json-schema.org/draft-07/schema#",
				"title":   "Email address",
				"type":    "object",
				"properties": map[string]any{
					"credentialSubject": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"emailAddress": map[string]any{
								"type": "string",
							},
						},
						"required": []string{"emailAddress"},
					},
				},
				"required": []string{"credentialSubject"},
			},
		},
		"credentialSchema": map[string]any{
			"id":        JSONSchemaCredentialSchemaID,
			"type":      "JsonSchema",
			"digestSRI": JSONSchemaCredentialDigestSRI,
		},
	}
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
