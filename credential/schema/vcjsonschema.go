package schema

import (
	"github.com/TBD54566975/did-sdk/schema"
	"github.com/goccy/go-json"

	"github.com/TBD54566975/did-sdk/credential"
	"github.com/gobuffalo/packr/v2"
)

const (
	verifiableCredentialJSONSchemaSchema string = "vc-json-schema.json"
	verifiableCredentialIDProperty       string = "id"
)

var (
	schemaBox = packr.New("Known JSON Schemas", "../known_schemas")
)

// StringToVCJSONCredentialSchema marshals a string into a credential json credential schema
func StringToVCJSONCredentialSchema(maybeVCJSONCredentialSchema string) (*VCJSONSchema, error) {
	if err := schema.IsValidJSONSchema(maybeVCJSONCredentialSchema); err != nil {
		return nil, err
	}
	var vcs VCJSONSchema
	if err := json.Unmarshal([]byte(maybeVCJSONCredentialSchema), &vcs); err != nil {
		return nil, err
	}
	return &vcs, nil
}

// IsValidCredentialSchema determines if a given credential schema is compliant with the specification's
// JSON Schema https://w3c-ccg.github.io/vc-json-schemas/v2/index.html#credential_schema_definition
func IsValidCredentialSchema(maybeCredentialSchema string) error {
	if err := schema.IsValidJSONSchema(maybeCredentialSchema); err != nil {
		return err
	}

	vcJSONSchemaSchema, err := getKnownSchema(verifiableCredentialJSONSchemaSchema)
	if err != nil {
		return err
	}

	return schema.IsJSONValidAgainstSchema(maybeCredentialSchema, vcJSONSchemaSchema)
}

func IsCredentialValidForVCJSONSchema(credential credential.VerifiableCredential, vcJSONSchema VCJSONSchema) error {
	schemaBytes, err := json.Marshal(vcJSONSchema.Schema)
	if err != nil {
		return err
	}
	return IsCredentialValidForSchema(credential, string(schemaBytes))
}

// IsCredentialValidForSchema determines whether a given Verifiable Credential is valid against
// a specified credential schema
func IsCredentialValidForSchema(credential credential.VerifiableCredential, s string) error {
	// First pull out credential subject and remove the ID property
	credSubjectMap := credential.CredentialSubject
	delete(credSubjectMap, verifiableCredentialIDProperty)

	// JSON-ify the subject
	subjectBytes, err := json.Marshal(credSubjectMap)
	if err != nil {
		return err
	}
	subjectJSON := string(subjectBytes)
	return schema.IsJSONValidAgainstSchema(subjectJSON, s)
}

func getKnownSchema(fileName string) (string, error) {
	return schemaBox.FindString(fileName)
}
