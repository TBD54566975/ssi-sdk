package validation

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

type CredentialValidator struct {
	validators []Validator
}

type Validator struct {
	ID           string
	ValidateFunc Validate
}

type (
	// OptionKey uniquely represents an option to be used in a validator
	OptionKey string
)

// Option represents a single option that may be required for a validator
type Option struct {
	ID     OptionKey
	Option any
}

// GetValidationOption returns a validation option given an ID
func GetValidationOption(opts []Option, id OptionKey) (any, error) {
	for _, opt := range opts {
		if opt.ID == id {
			return opt.Option, nil
		}
	}
	return nil, errors.Errorf("option with id <%s> not found", id)
}

type Validate func(cred credential.VerifiableCredential, opts ...Option) error

// NewCredentialValidator creates a new credential validator which executes in the order of the validators provided
// The validators introspect the contents of the credential, and do not handle signature verification.
func NewCredentialValidator(validators []Validator) (*CredentialValidator, error) {
	// dedupe
	var deduplicatedValidators []Validator
	validatorCheck := make(map[string]bool)
	for _, validator := range validators {
		if _, ok := validatorCheck[validator.ID]; !ok {
			validatorCheck[validator.ID] = true
			deduplicatedValidators = append(deduplicatedValidators, validator)
		}
	}
	if len(deduplicatedValidators) == 0 {
		return nil, errors.New("no validators provided")
	}
	return &CredentialValidator{validators: deduplicatedValidators}, nil
}

// ValidateCredential validates a credential given a credential validator
func (cv *CredentialValidator) ValidateCredential(cred credential.VerifiableCredential, opts ...Option) error {
	ae := util.NewAppendError()
	for _, validator := range cv.validators {
		if err := validator.ValidateFunc(cred, opts...); err != nil {
			ae.AppendString(fmt.Sprintf("[validator: %s]: %s", validator.ID, err.Error()))
		}
	}
	if !ae.IsEmpty() {
		return fmt.Errorf("credential validation failed with <%d> error, %s", ae.NumErrors(), ae.Error().Error())
	}
	return nil
}
