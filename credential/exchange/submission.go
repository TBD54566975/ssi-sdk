package exchange

import (
	"fmt"
	"github.com/TBD54566975/did-sdk/credential"
	"github.com/TBD54566975/did-sdk/credential/signing"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/pkg/errors"
)

// EmbedTarget describes where a presentation_submission is located in an object model
// https://identity.foundation/presentation-exchange/#embed-targets
type EmbedTarget string

const (
	// JWTVPTarget is an embed target where a presentation submission is represented alongside a Verifiable Presentation
	// in a JWT value. `presentation_submission` is a top-level claim alongside `vc` for the VP
	JWTVPTarget EmbedTarget = "jwt_vp"
	//JWTTarget   EmbedTarget = "jwt"
	//LDPVPTarget EmbedTarget = "ldp_vp"
)

// PresentationClaim 's may be of any claim format designation, including LD or JWT variations of VCs or VPs
// https://identity.foundation/presentation-exchange/#claim-format-designations
type PresentationClaim struct {
	Credential   *credential.VerifiableCredential
	Presentation *credential.VerifiablePresentation
	Token        *string
	Format       ClaimFormat
}

// BuildPresentationSubmission constructs a submission given a presentation definition, set of claims, and an
// embed target format.
// https://identity.foundation/presentation-exchange/#presentation-submission
func BuildPresentationSubmission(signer cryptosuite.Signer, def PresentationDefinition, claims []PresentationClaim, et EmbedTarget) ([]byte, error) {
	if !IsSupportedEmbedTarget(et) {
		return nil, fmt.Errorf("unsupported presentation submission embed target type: %s", et)
	}
	switch et {
	case JWTVPTarget:
		jwkSigner, ok := signer.(*cryptosuite.JSONWebKeySigner)
		if !ok {
			return nil, fmt.Errorf("signer not valid for request type: %s", et)
		}
		vpSubmission, err := BuildPresentationSubmissionVP(def, claims)
		if err != nil {
			return nil, errors.Wrap(err, "unable to fulfill presentation definition with given credentials")
		}
		return signing.SignVerifiablePresentationJWT(*jwkSigner, *vpSubmission)
	default:
		return nil, fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
	}
}

func BuildPresentationSubmissionVP(def PresentationDefinition, claims []PresentationClaim) (*credential.VerifiablePresentation, error) {

	return nil, nil
}

func VerifyPresentationSubmission() error {
	return nil
}

func IsSupportedEmbedTarget(et EmbedTarget) bool {
	supported := GetSupportedEmbedTargets()
	for _, t := range supported {
		if et == t {
			return true
		}
	}
	return false
}

func GetSupportedEmbedTargets() []EmbedTarget {
	return []EmbedTarget{JWTVPTarget}
}
