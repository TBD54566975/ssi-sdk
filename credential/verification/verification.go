package verification

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
)

// CredentialVerifier does three levels of verification on a credential:
// 1. Makes sure the credential has a valid signature
// 2. Makes sure the credential has is not expired
// 3. Makes sure the credential complies with the VC Data Model
// 4. If the credential has a schema, makes sure its data complies with the schema
// LATER: Makes sure the credential has not been revoked, other checks.
// Note: https://github.com/TBD54566975/ssi-sdk/issues/213
type CredentialVerifier struct {
	verifiers []Verifier
}

type Verifier struct {
	Description string
	VerifyFunc  Verify
}

type Verify func(credential.VerifiableCredential) error

// NewCredentialVerifier creates a new credential verifier
func NewCredentialVerifier(verifiers []Verifier) (*CredentialVerifier, error) {
	// dedupe
	var res []Verifier
	verifierCheck := make(map[string]bool)
	for _, verifier := range verifiers {
		if _, ok := verifierCheck[verifier.Description]; !ok {
			verifierCheck[verifier.Description] = true
			res = append(res, verifier)
		}
	}
	if len(res) == 0 {
		return nil, errors.New("no verifiers provided")
	}
	return &CredentialVerifier{verifiers: res}, nil
}

// VerifyCredential verifies a credential given a credential verifier
func (cv *CredentialVerifier) VerifyCredential(cred credential.VerifiableCredential) error {
	ae := util.NewAppendError()
	for _, verifier := range cv.verifiers {
		if err := verifier.VerifyFunc(cred); err != nil {
			ae.AppendString(fmt.Sprintf("[failed] for %s: %s", verifier.Description, err.Error()))
		}
	}
	if !ae.IsEmpty() {
		return errors.Wrapf(ae.Error(), "credential verification failed with [%d]: %", ae.NumErrors())
	}
	return nil
}
