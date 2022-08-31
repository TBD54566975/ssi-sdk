package pkg

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/sirupsen/logrus"
)

var authorizationError = errors.New("insufficient claims provided")

// This is a very simple validation process.
// against a Presentation Submission
// It checks:
// 1. That the VC is valid
// 2. That the VC was issued by a trusted entity
func ValidateAccess(verifier cryptosuite.JSONWebKeyVerifier, data []byte) error {

	vp, err := signing.VerifyVerifiablePresentationJWT(verifier, string(data))
	if err != nil {
		return err
	}

	if err := vp.IsValid(); err != nil {
		return fmt.Errorf("failed to vaildate vp: %s", err.Error())
	}

	for _, untypedCredential := range vp.VerifiableCredential {
		var vc credential.VerifiableCredential

		if dat, err := json.Marshal(untypedCredential); err == nil {

			if err := json.Unmarshal(dat, &vc); err != nil {
				logrus.Error(err)
			}

			if issuer, ok := vc.CredentialSubject["id"]; ok && TrustedEntities.isTrusted(issuer.(string)) {
				authorizationError = nil
			}

		}
	}
	return authorizationError
}
