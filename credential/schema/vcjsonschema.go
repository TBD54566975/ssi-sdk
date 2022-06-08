package schema

import (
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/ssi-sdk/schema"

	"github.com/gobuffalo/packr/v2"

	"github.com/TBD54566975/ssi-sdk/credential"
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
	var vcs VCJSONSchema
	if err := json.Unmarshal([]byte(maybeVCJSONCredentialSchema), &vcs); err != nil {
		return nil, err
	}

	schemaBytes, err := json.Marshal(vcs.Schema)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal vc json schema's schema property")
	}
	maybeSchema := string(schemaBytes)
	if err := schema.IsValidJSONSchema(maybeSchema); err != nil {
		errMsg := "VC JSON Schema did not contain a valid JSON Schema"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}
	return &vcs, nil
}

// IsValidCredentialSchema determines if a given credential schema is compliant with the specification's
// JSON Schema https://w3c-ccg.github.io/vc-json-schemas/v2/index.html#credential_schema_definition
func IsValidCredentialSchema(maybeCredentialSchema string) error {
	vcJSONSchemaSchema, err := getKnownSchema(verifiableCredentialJSONSchemaSchema)
	if err != nil {
		return errors.Wrap(err, "could not get known schema for VC JSON Schema")
	}

	if err := schema.IsJSONValidAgainstSchema(maybeCredentialSchema, vcJSONSchemaSchema); err != nil {
		errMsg := "credential schema did not validate"
		logrus.WithError(err).Error(errMsg)
		return errors.Wrap(err, errMsg)
	}

	if _, err := StringToVCJSONCredentialSchema(maybeCredentialSchema); err != nil {
		errMsg := "credential schema not valid"
		logrus.WithError(err).Error(errMsg)
		return errors.Wrap(err, errMsg)
	}

	return nil
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
	if err := schema.IsJSONValidAgainstSchema(subjectJSON, s); err != nil {
		logrus.WithError(err).Error("credential not valid for schema")
		return err
	}
	return nil
}

func getKnownSchema(fileName string) (string, error) {
	return schemaBox.FindString(fileName)
}
