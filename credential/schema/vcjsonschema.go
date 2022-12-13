package schema

import (
	"embed"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

var (
	//go:embed known_schemas
	knownSchemas embed.FS
)

type VCJSONSchemaSchema string

func (vcj VCJSONSchemaSchema) String() string {
	return string(vcj)
}

const (
	VerifiableCredentialJSONSchemaSchema VCJSONSchemaSchema = "vc-json-schema.json"
)

// StringToVCJSONCredentialSchema marshals a string into a credential json credential schema
func StringToVCJSONCredentialSchema(maybeVCJSONCredentialSchema string) (*VCJSONSchema, error) {
	var vcs VCJSONSchema
	if err := json.Unmarshal([]byte(maybeVCJSONCredentialSchema), &vcs); err != nil {
		return nil, err
	}

	schemaBytes, err := json.Marshal(vcs.Schema)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal vc json schema's schema property")
	}
	maybeSchema := string(schemaBytes)
	if err = schema.IsValidJSONSchema(maybeSchema); err != nil {
		return nil, errors.Wrap(err, "vc json schema did not contain a valid JSON Schema")
	}
	return &vcs, nil
}

// IsValidCredentialSchema determines if a given credential schema is compliant with the specification's
// JSON Schema https://w3c-ccg.github.io/vc-json-schemas/v2/index.html#credential_schema_definition
func IsValidCredentialSchema(maybeCredentialSchema string) error {
	vcJSONSchemaSchema, err := GetVCJSONSchema(VerifiableCredentialJSONSchemaSchema)
	if err != nil {
		return errors.Wrap(err, "could not get known schema for VC JSON Schema")
	}

	if err = schema.IsJSONValidAgainstSchema(maybeCredentialSchema, vcJSONSchemaSchema); err != nil {
		return errors.Wrap(err, "credential schema did not validate")
	}

	if _, err = StringToVCJSONCredentialSchema(maybeCredentialSchema); err != nil {
		return errors.Wrap(err, "credential schema not valid")
	}

	return nil
}

func IsCredentialValidForVCJSONSchema(cred credential.VerifiableCredential, vcJSONSchema VCJSONSchema) error {
	schemaBytes, err := json.Marshal(vcJSONSchema.Schema)
	if err != nil {
		return err
	}
	return IsCredentialValidForSchema(cred, string(schemaBytes))
}

// IsCredentialValidForSchema determines whether a given Verifiable Credential is valid against
// a specified credential schema
func IsCredentialValidForSchema(cred credential.VerifiableCredential, s string) error {
	// First pull out credential subject and remove the ID property
	credSubjectMap := cred.CredentialSubject

	gotID, _ := credSubjectMap[credential.VerifiableCredentialIDProperty]
	delete(credSubjectMap, credential.VerifiableCredentialIDProperty)

	// set the id back after validation
	defer func() { credSubjectMap[credential.VerifiableCredentialIDProperty] = gotID }()

	// JSON-ify the subject
	subjectBytes, err := json.Marshal(credSubjectMap)
	if err != nil {
		return err
	}
	subjectJSON := string(subjectBytes)
	if err = schema.IsJSONValidAgainstSchema(subjectJSON, s); err != nil {
		return errors.Wrap(err, "credential not valid for schema")
	}
	return nil
}

func GetVCJSONSchema(schemaFile VCJSONSchemaSchema) (string, error) {
	b, err := knownSchemas.ReadFile("known_schemas/" + schemaFile.String())
	return string(b), err
}
