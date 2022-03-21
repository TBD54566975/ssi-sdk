package exchange

import (
	"fmt"
	"github.com/TBD54566975/did-sdk/credential"
)

// EmbedTarget describes where a presentation_submission is located in an object model
// https://identity.foundation/presentation-exchange/#embed-targets
type EmbedTarget string

const (
	// JWTVPTarget is an embed target where a presentation submission is represented alongside a Verifiable Presentation
	// in a JWT value. `presentation_submission` is a top-level claim alongside `vc` for the VP
	JWTVPTarget EmbedTarget = "jwt_vp"
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
func BuildPresentationSubmission(def PresentationDefinition, claims []PresentationClaim, et EmbedTarget) ([]byte, error) {
	if !IsSupportedEmbedTarget(et) {
		return nil, fmt.Errorf("unsupported presentation submission embed target type: %s", et)
	}
	switch et {
	case JWTVPTarget:
		return BuildPresentationSubmissionJWTVP(def, claims)
	default:
		return nil, fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
	}
}

func BuildPresentationSubmissionJWTVP(def PresentationDefinition, claims []PresentationClaim) ([]byte, error) {
	return nil, nil
}

func VerifyPresentationSubmission() {

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
