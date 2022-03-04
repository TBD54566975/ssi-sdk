package schema

import (
	"github.com/goccy/go-json"

	"github.com/TBD54566975/did-sdk/vc"
	"github.com/gobuffalo/packr/v2"
)

const (
	VerifiableCredentialJSONSchemaSchema string = "vc-json-schema.json"
	VerifiableCredentialIDProperty       string = "id"
)

var (
	knownSchemaBox = packr.New("Known JSON Schemas", "./known_schemas")
)

// StringToVCJSONCredentialSchema marshals a string into a vc json credential schema
func StringToVCJSONCredentialSchema(maybeVCJSONCredentialSchema string) (*VCJSONSchema, error) {
	if err := IsValidJSONSchema(maybeVCJSONCredentialSchema); err != nil {
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
	if err := IsValidJSONSchema(maybeCredentialSchema); err != nil {
		return err
	}

	vcJSONSchemaSchema, err := getKnownSchema(VerifiableCredentialJSONSchemaSchema)
	if err != nil {
		return err
	}

	return IsJSONValidAgainstSchema(maybeCredentialSchema, vcJSONSchemaSchema)
}

func IsCredentialValidForVCJSONSchema(credential vc.VerifiableCredential, vcJSONSchema VCJSONSchema) error {
	schemaBytes, err := json.Marshal(vcJSONSchema.Schema)
	if err != nil {
		return err
	}
	return IsCredentialValidForSchema(credential, string(schemaBytes))
}

// IsCredentialValidForSchema determines whether a given Verifiable Credential is valid against
// a specified credential schema
func IsCredentialValidForSchema(credential vc.VerifiableCredential, schema string) error {
	// First pull out credential subject and remove the ID property
	credSubjectMap := credential.CredentialSubject
	delete(credSubjectMap, VerifiableCredentialIDProperty)

	// JSON-ify the subject
	subjectBytes, err := json.Marshal(credSubjectMap)
	if err != nil {
		return err
	}
	subjectJSON := string(subjectBytes)
	return IsJSONValidAgainstSchema(subjectJSON, schema)
}

func getKnownSchema(fileName string) (string, error) {
	return knownSchemaBox.FindString(fileName)
}
