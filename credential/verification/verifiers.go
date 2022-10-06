package verification

import (
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	credschema "github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/pkg/errors"
)

const (
	SchemaOption OptionKey = "schema"
)

var KnownVerifiers = []Verifier{
	{
		ID:         "Go Validation",
		VerifyFunc: VerifyValidCredential,
	},
	{
		ID:         "Expiry",
		VerifyFunc: VerifyExpiry,
	},
	{
		ID:         "VC JSON Schema",
		VerifyFunc: VerifyJSONSchema,
	},
}

// VerifyValidCredential verifies a credential's object model depending on the struct tags used on VerifiableCredential
// TODO(gabe) add support for JSON schema validation of the VCDM after https://github.com/w3c/vc-data-model/issues/934
func VerifyValidCredential(credential credential.VerifiableCredential, _ ...VerificationOption) error {
	return credential.IsValid()
}

// VerifyExpiry verifies a credential's expiry date is not in the past. We assume the date is parseable as
// an RFC3339 date time value.
func VerifyExpiry(credential credential.VerifiableCredential, _ ...VerificationOption) error {
	if credential.ExpirationDate == "" {
		return nil
	}
	expiryTime, err := time.Parse(time.RFC3339, credential.ExpirationDate)
	if err != nil {
		return errors.Wrapf(err, "failed to parse expiry date: %s", credential.ExpirationDate)
	}
	if expiryTime.Before(time.Now()) {
		return fmt.Errorf("credential has expired as of %s", expiryTime.String())
	}
	return nil
}

// WithSchema provides a schema as a verification option
func WithSchema(schema string) VerificationOption {
	return VerificationOption{
		ID:     SchemaOption,
		Option: schema,
	}
}

// VerifyJSONSchema verifies a credential's data against a Verifiable Credential JSON Schema:
// https://w3c-ccg.github.io/vc-json-schemas/v2/index.html#credential_schema_definition
// There is a required single option which is a string JSON value representing the Credential Schema Object
func VerifyJSONSchema(credential credential.VerifiableCredential, opts ...VerificationOption) error {
	hasSchemaProperty := credential.CredentialSchema != nil
	schema, err := GetVerificationOption(opts, SchemaOption)
	if err != nil {
		// if the credential does not have a schema property, we cannot perform this check
		if !hasSchemaProperty {
			return nil
		}
		return errors.Wrap(err, "cannot verify the credential against a JSON schema, no schema provided")
	}
	// if the credential does not have a schema property, we cannot perform this check
	if !hasSchemaProperty {
		return errors.New("credential does not have a credentialSchema property")
	}
	credSchema, err := optionToCredentialSchema(schema)
	if err != nil {
		return err
	}
	return credschema.IsCredentialValidForVCJSONSchema(credential, *credSchema)
}

func optionToCredentialSchema(maybeSchema interface{}) (*credschema.VCJSONSchema, error) {
	schema, ok := maybeSchema.(string)
	if !ok {
		return nil, errors.New("the option provided must be a string value representing a Verifiable Credential JSON Schema")
	}
	if err := credschema.IsValidCredentialSchema(schema); err != nil {
		return nil, errors.Wrap(err, "credential schema is invalid")
	}
	return credschema.StringToVCJSONCredentialSchema(schema)
}
