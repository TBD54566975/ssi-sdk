package schema

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

type VCJSONSchemaAccess interface {
	// GetVCJSONSchema returns a vc json schema for the given ID as a json string
	GetVCJSONSchema(id string) (string, error)
}

// IsCredentialValidForJSONSchema validates a credential against a schema, returning an error if it is not valid
func IsCredentialValidForJSONSchema(cred credential.VerifiableCredential, s JSONSchema) error {
	schemaBytes, err := json.Marshal(s)
	if err != nil {
		return err
	}
	credBytes, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	if err = schema.IsValidAgainstJSONSchema(string(credBytes), string(schemaBytes)); err != nil {
		return errors.Wrap(err, "credential not valid for schema")
	}
	return nil
}

// GetCredentialSchemaFromCredential returns the credential schema and type for a given credential given
// a credential schema access, which is used to retrieve the schema
func GetCredentialSchemaFromCredential(access VCJSONSchemaAccess, cred credential.VerifiableCredential) (string, VCJSONSchemaType, error) {
	if cred.CredentialSchema == nil {
		return "", "", errors.New("credential does not contain a credential schema")
	}

	jsonSchema, err := access.GetVCJSONSchema(cred.CredentialSchema.ID)
	if err != nil {
		return "", "", errors.Wrap(err, "error getting schema")
	}

	if !IsSupportedVCJSONSchemaType(cred.CredentialSchema.Type) {
		return "", "", fmt.Errorf("credential schema type<%T> is not supported", cred.CredentialSchema.Type)
	}
	return jsonSchema, VCJSONSchemaType(cred.CredentialSchema.Type), nil
}
