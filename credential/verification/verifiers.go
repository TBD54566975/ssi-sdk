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
		ID:         "Object Validation",
		VerifyFunc: VerifyValidCredential,
	},
	{
		ID:         "Expiry Check",
		VerifyFunc: VerifyExpiry,
	},
	{
		ID:         "VC JSON Schema",
		VerifyFunc: VerifyJSONSchema,
	},
}

// VerifyValidCredential verifies a credential's object model depending on the struct tags used on VerifiableCredential
// TODO(gabe) add support for JSON schema validation of the VCDM after https://github.com/w3c/vc-data-model/issues/934
func VerifyValidCredential(cred credential.VerifiableCredential, _ ...VerificationOption) error {
	return cred.IsValid()
}

// VerifyExpiry verifies a credential's expiry date is not in the past. We assume the date is parseable as
// an RFC3339 date time value.
func VerifyExpiry(cred credential.VerifiableCredential, _ ...VerificationOption) error {
	if cred.ExpirationDate == "" {
		return nil
	}
	expiryTime, err := time.Parse(time.RFC3339, cred.ExpirationDate)
	if err != nil {
		return errors.Wrapf(err, "failed to parse expiry date: %s", cred.ExpirationDate)
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
func VerifyJSONSchema(cred credential.VerifiableCredential, opts ...VerificationOption) error {
	hasSchemaProperty := cred.CredentialSchema != nil
	schema, err := GetVerificationOption(opts, SchemaOption)
	if err != nil {
		// if the cred does not have a schema property, we cannot perform this check
		if !hasSchemaProperty {
			return nil
		}
		return errors.Wrap(err, "cannot verify the credential against a JSON schema, no schema provided")
	}
	// if the cred does not have a schema property, we cannot perform this check
	if !hasSchemaProperty {
		return errors.New("credential does not have a credentialSchema property")
	}
	credSchema, err := optionToCredentialSchema(schema)
	if err != nil {
		return err
	}
	return credschema.IsCredentialValidForVCJSONSchema(cred, *credSchema)
}

func optionToCredentialSchema(maybeSchema any) (*credschema.VCJSONSchema, error) {
	schema, ok := maybeSchema.(string)
	if !ok {
		return nil, errors.New("the option provided must be a string value representing a Verifiable Credential JSON Schema")
	}
	if err := credschema.IsValidCredentialSchema(schema); err != nil {
		return nil, errors.Wrap(err, "credential schema is invalid")
	}
	return credschema.StringToVCJSONCredentialSchema(schema)
}
