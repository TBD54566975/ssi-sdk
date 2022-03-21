package exchange

import "github.com/TBD54566975/did-sdk/credential"

type PresentationClaim struct {
	Credential   *credential.VerifiableCredential
	Presentation *credential.VerifiablePresentation
	Token        *string
	ClaimFormat
}

func BuildPresentationSubmission(claims []PresentationClaim) {

}

func VerifyPresentationSubmission() {

}
