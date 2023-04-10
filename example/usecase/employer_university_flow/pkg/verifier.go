package pkg

import (
	"github.com/goccy/go-json"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/pkg/errors"
)

// ValidateAccess is a very simple validation process against a Presentation Submission
// It checks:
// 1. That the VC is valid
// 2. That the VC was issued by a trusted entity
func ValidateAccess(verifier crypto.JWTVerifier, credBytes []byte) error {
	_, _, vp, err := signing.VerifyVerifiablePresentationJWT(verifier, string(credBytes))
	if err != nil {
		return errors.Wrap(err, "failed to validate VP signature")
	}

	if err = vp.IsValid(); err != nil {
		return errors.Wrap(err, "failed to validate VP")
	}

	for _, untypedCredential := range vp.VerifiableCredential {
		credBytes, err = json.Marshal(untypedCredential)
		if err != nil {
			return errors.Wrap(err, "could not marshal credential in VP")
		}
		var vc credential.VerifiableCredential
		if err = json.Unmarshal(credBytes, &vc); err != nil {
			return errors.Wrap(err, "could not unmarshal credential in VP")
		}
		// validity check
		if issuer, ok := vc.CredentialSubject["id"]; !ok || !TrustedEntities.isTrusted(issuer.(string)) {
			return errors.New("insufficient claims provided")
		}
	}
	return nil
}
