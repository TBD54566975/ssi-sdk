package pkg

import (
	"context"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/pkg/errors"
)

// ValidateAccess is a very simple validation process against a Presentation Submission
// It checks:
// 1. That the VP is valid
// 2. All VCs in the VP are valid
// 2. That the VC was issued by a trusted entity (implied by the presentation, according to the Presentation Definition)
func ValidateAccess(verifier crypto.JWTVerifier, resolver did.Resolver, submissionBytes []byte) error {
	_, _, vp, err := credential.VerifyVerifiablePresentationJWT(context.Background(), verifier, resolver, string(submissionBytes))
	if err != nil {
		return errors.Wrap(err, "failed to validate VP signature")
	}

	if err = vp.IsValid(); err != nil {
		return errors.Wrap(err, "failed to validate VP")
	}
	return nil
}
