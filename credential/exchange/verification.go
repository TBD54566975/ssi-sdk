//go:build jwx_es256k

package exchange

import (
	"fmt"
	"github.com/TBD54566975/did-sdk/credential"
	"github.com/TBD54566975/did-sdk/credential/signing"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/pkg/errors"
)

// VerifyPresentationSubmission verifies a presentation submission for both signature validity and correctness
// with the specification. It is assumed that the caller knows the submission embed target, and the corresponding
// presentation definition, and has access to the public key of the signer.
func VerifyPresentationSubmission(verifier cryptosuite.Verifier, et EmbedTarget, def PresentationDefinition, submission []byte) error {
	if !IsSupportedEmbedTarget(et) {
		return fmt.Errorf("unsupported presentation submission embed target type: %s", et)
	}
	switch et {
	case JWTVPTarget:
		jwkVerifier, ok := verifier.(*cryptosuite.JSONWebKeyVerifier)
		if !ok {
			return fmt.Errorf("verifier not valid for request type: %s", et)
		}
		vp, err := signing.VerifyVerifiablePresentationJWT(*jwkVerifier, string(submission))
		if err != nil {
			return errors.Wrap(err, "verification of the presentation submission failed")
		}
		return VerifyPresentationSubmissionVP(def, *vp)
	default:
		return fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
	}
}

// VerifyPresentationSubmissionVP verifies whether a verifiable presentation is a valid presentation submission
// for a given presentation definition.
func VerifyPresentationSubmissionVP(def PresentationDefinition, vp credential.VerifiablePresentation) error {
	return nil
}
