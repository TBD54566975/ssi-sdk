package verification

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

type CredentialVerifier struct {
	verifiers []Verifier
}

type Verifier struct {
	ID         string
	VerifyFunc Verify
}

type (
	// OptionKey uniquely represents an option to be used in a verifier
	OptionKey string
)

// VerificationOption represents a single option that may be required for a verifier
type VerificationOption struct {
	ID     OptionKey
	Option any
}

// GetVerificationOption returns a verification option given an id
func GetVerificationOption(opts []VerificationOption, id OptionKey) (any, error) {
	for _, opt := range opts {
		if opt.ID == id {
			return opt.Option, nil
		}
	}
	return nil, errors.Errorf("option with id <%s> not found", id)
}

type Verify func(cred credential.VerifiableCredential, opts ...VerificationOption) error

// NewCredentialVerifier creates a new credential verifier which executes in the order of the verifiers provided
func NewCredentialVerifier(verifiers []Verifier) (*CredentialVerifier, error) {
	// dedupe
	var deduplicatedVerifiers []Verifier
	verifierCheck := make(map[string]bool)
	for _, verifier := range verifiers {
		if _, ok := verifierCheck[verifier.ID]; !ok {
			verifierCheck[verifier.ID] = true
			deduplicatedVerifiers = append(deduplicatedVerifiers, verifier)
		}
	}
	if len(deduplicatedVerifiers) == 0 {
		return nil, errors.New("no verifiers provided")
	}
	return &CredentialVerifier{verifiers: deduplicatedVerifiers}, nil
}

// VerifyCredential verifies a credential given a credential verifier
func (cv *CredentialVerifier) VerifyCredential(cred credential.VerifiableCredential, opts ...VerificationOption) error {
	ae := util.NewAppendError()
	for _, verifier := range cv.verifiers {
		if err := verifier.VerifyFunc(cred, opts...); err != nil {
			ae.AppendString(fmt.Sprintf("[validator: %s]: %s", verifier.ID, err.Error()))
		}
	}
	if !ae.IsEmpty() {
		return fmt.Errorf("credential verification failed with <%d> error, %s", ae.NumErrors(), ae.Error().Error())
	}
	return nil
}
