package validation

import (
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	credschema "github.com/TBD54566975/ssi-sdk/credential/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

const (
	SchemaOption OptionKey = "schema"
)

// ValidateCredential verifies a credential's object model depending on the struct tags used on VerifiableCredential
func ValidateCredential(cred credential.VerifiableCredential, _ ...Option) error {
	return cred.IsValid()
}

// ValidateExpiry verifies a credential's expiry date is not in the past. We assume the date is parseable as
// an RFC3339 date time value.
func ValidateExpiry(cred credential.VerifiableCredential, _ ...Option) error {
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

// WithSchema provides a schema as a validation option
func WithSchema(schema string) Option {
	return Option{
		ID:     SchemaOption,
		Option: schema,
	}
}

// ValidateJSONSchema verifies a credential's data against a Verifiable Credential JSON Schema
// There is a required single option which is a string JSON value representing the Credential Schema Object
func ValidateJSONSchema(cred credential.VerifiableCredential, opts ...Option) error {
	hasSchemaProperty := cred.CredentialSchema != nil
	schema, err := GetValidationOption(opts, SchemaOption)
	if err != nil {
		// if the cred does not have a schema property, we cannot perform this check
		if !hasSchemaProperty {
			return nil
		}
		return errors.Wrap(err, "cannot validate the credential against a JSON schema, no schema provided")
	}
	// if the cred does not have a schema property, we cannot perform this check
	if !hasSchemaProperty {
		return errors.New("credential does not have a credentialSchema property")
	}
	schemaType := cred.CredentialSchema.Type
	credSchema, err := optionToCredentialSchema(schema)
	if err != nil {
		return err
	}
	return credschema.IsCredentialValidForJSONSchema(cred, *credSchema, credschema.VCJSONSchemaType(schemaType))
}

func optionToCredentialSchema(maybeSchema any) (*credschema.VCJSONSchema, error) {
	schema, ok := maybeSchema.(string)
	if !ok {
		return nil, errors.New("the option provided must be a string value representing a Verifiable Credential JSON Schema")
	}
	var credSchema credschema.VCJSONSchema
	if err := json.Unmarshal([]byte(schema), &credSchema); err != nil {
		return nil, errors.Wrap(err, "credential schema is invalid")
	}
	return &credSchema, nil
}

func GetKnownVerifiers() []Validator {
	return []Validator{
		{
			ID:           "Data Model Validation",
			ValidateFunc: ValidateCredential,
		},
		{
			ID:           "Expiry Check",
			ValidateFunc: ValidateExpiry,
		},
		{
			ID:           "VC JSON Schema",
			ValidateFunc: ValidateJSONSchema,
		},
	}
}
