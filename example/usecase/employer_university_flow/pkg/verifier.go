package pkg

import (
	"encoding/json"
	"errors"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/util"
)

// ValidateAccess is a very simple validation process against a Presentation Submission  It checks:
// 1. That the VC is valid
// 2. That the VC was issued by a trusted entity
func ValidateAccess(verifier crypto.JWTVerifier, data []byte) error {
	vp, err := signing.VerifyVerifiablePresentationJWT(verifier, string(data))
	if err != nil {
		return util.LoggingErrorMsg(err, "failed to validate VP signature")
	}

	if err := vp.IsValid(); err != nil {
		return util.LoggingErrorMsg(err, "failed to validate VP")
	}

	for _, untypedCredential := range vp.VerifiableCredential {
		data, err := json.Marshal(untypedCredential)
		if err != nil {
			return util.LoggingErrorMsg(err, "could not marshal credential in VP")
		}
		var vc credential.VerifiableCredential
		if err := json.Unmarshal(data, &vc); err != nil {
			return util.LoggingErrorMsg(err, "could not unmarshal credential in VP")
		}
		// validity check
		if issuer, ok := vc.CredentialSubject["id"]; !ok || !TrustedEntities.isTrusted(issuer.(string)) {
			return errors.New("insufficient claims provided")
		}
	}
	return nil
}
