package schema

import (
	"context"
	"fmt"
	"net/url"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// ValidateCredentialAgainstSchema validates a credential against a schema, returning an error if it is not valid
// The schema is retrieved from the given VCJSONSchemaAccess using the credential's credential schema ID
func ValidateCredentialAgainstSchema(access VCJSONSchemaAccess, cred credential.VerifiableCredential) error {
	vcJSONSchema, vcJSONSchemaType, err := GetCredentialSchemaFromCredential(access, cred)
	if err != nil {
		return errors.Wrap(err, "getting schema from credential")
	}
	if err = IsCredentialValidForJSONSchema(cred, vcJSONSchema, vcJSONSchemaType); err != nil {
		return errors.Wrap(err, "credential not valid for schema")
	}
	return nil
}

// IsCredentialValidForJSONSchema validates a credential against a schema, returning an error if it is not valid
func IsCredentialValidForJSONSchema(cred credential.VerifiableCredential, vcs VCJSONSchema, t VCJSONSchemaType) error {
	if cred.IsEmpty() {
		return errors.New("credential is empty")
	}
	if len(vcs) == 0 {
		return errors.New("credential schema is empty")
	}

	credsSchemaType := cred.CredentialSchema.Type
	if !IsSupportedVCJSONSchemaType(credsSchemaType) {
		return fmt.Errorf("credential schema type<%s> is not supported", credsSchemaType)
	}
	if credsSchemaType != t.String() {
		return fmt.Errorf("credential schema type<%s> does not match schema type<%s>", credsSchemaType, t)
	}

	var schemaID string
	var s JSONSchema
	switch t {
	case JSONSchemaType:
		s = JSONSchema(vcs)
		schemaID = s.ID()
	case JSONSchemaCredentialType:
		var err error
		s, schemaID, err = parseJSONSchemaCredential(vcs)
		if err != nil {
			return errors.Wrap(err, "parsing credential schema")
		}
	}

	// check the ID is a valid URI
	if ok := isValidURI(s.ID()); !ok {
		return fmt.Errorf("credential schema ID<%s> is not a valid URI", s.ID())
	}

	// check if the ID in the credential's credentialSchema matches the ID of the schema
	if cred.CredentialSchema.ID != schemaID {
		return fmt.Errorf("credential schema ID<%s> does not match schema ID<%s>", cred.CredentialSchema.ID, schemaID)
	}

	// check if the $schema property is present and valid
	if s.Schema() == "" {
		return errors.New("credential schema does not contain a `$schema` property")
	}
	if !IsSupportedJSONSchemaVersion(s.Schema()) {
		return fmt.Errorf("schema version<%s> is not supported", s.Schema())
	}

	// check if the credential is valid against the schema
	schemaBytes, err := json.Marshal(s)
	if err != nil {
		return errors.Wrap(err, "marshalling schema")
	}
	credBytes, err := json.Marshal(cred)
	if err != nil {
		return errors.Wrap(err, "marshalling credential")
	}
	if err = schema.IsValidAgainstJSONSchema(string(credBytes), string(schemaBytes)); err != nil {
		return errors.Wrap(err, "credential not valid for schema")
	}
	return nil
}

// JsonSchemaCredential helper for IsCredentialValidForJSONSchema
func parseJSONSchemaCredential(vcs VCJSONSchema) (JSONSchema, string, error) {
	var vc credential.VerifiableCredential
	schemaString := vcs.String()
	if err := json.Unmarshal([]byte(schemaString), &vc); err != nil {
		return nil, "", errors.Wrap(err, "unmarshalling schema")
	}
	schemaType, ok := vc.CredentialSubject[TypeProperty]
	if !ok {
		return nil, "", errors.New("credential schema's credential subject does not contain a `type`")
	}
	if schemaType != JSONSchemaType.String() {
		return nil, "", fmt.Errorf("credential schema's credential subject type<%s> does not match schema type<%s>", schemaType, JSONSchemaType)
	}
	if vc.CredentialSchema == nil {
		return nil, "", errors.New("credential schema's credential subject does not contain a `credentialSchema`")
	}
	credSchema := vc.CredentialSchema
	if credSchema.ID != JSONSchemaCredentialSchemaID {
		return nil, "", fmt.Errorf("credential schema's credential schema id<%s> does not match known id<%s>", credSchema.ID, JSONSchemaCredentialSchemaID)
	}
	if credSchema.Type != JSONSchemaType.String() {
		return nil, "", fmt.Errorf("credential schema's credential schema type<%s> does not match known type<%s>", credSchema.Type, JSONSchemaType)
	}
	if credSchema.DigestSRI != JSONSchemaCredentialDigestSRI {
		return nil, "", fmt.Errorf("credential schema's credential schema digest sri<%s> does not match known sri<%s>", credSchema.DigestSRI, JSONSchemaCredentialDigestSRI)
	}

	s := vc.CredentialSubject.GetJSONSchema()
	if len(s) == 0 {
		return nil, "", errors.New("credential schema's credential subject does not contain a valid `jsonSchema`")
	}
	schemaID := vc.ID
	return s, schemaID, nil
}

// GetCredentialSchemaFromCredential returns the credential schema and type for a given credential given
// a credential schema access, which is used to retrieve the schema
func GetCredentialSchemaFromCredential(access VCJSONSchemaAccess, cred credential.VerifiableCredential) (VCJSONSchema, VCJSONSchemaType, error) {
	if cred.CredentialSchema == nil {
		return nil, "", errors.New("credential does not contain a credential schema")
	}

	t := cred.CredentialSchema.Type
	if !IsSupportedVCJSONSchemaType(t) {
		return nil, "", fmt.Errorf("credential schema type<%s> is not supported", t)
	}

	jsonSchema, err := access.GetVCJSONSchema(context.Background(), VCJSONSchemaType(t), cred.CredentialSchema.ID)
	if err != nil {
		return nil, "", errors.Wrap(err, "getting schema")
	}
	return jsonSchema, VCJSONSchemaType(t), nil
}

func isValidURI(input string) bool {
	_, err := url.ParseRequestURI(input)
	return err == nil
}
