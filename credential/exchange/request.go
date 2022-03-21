package exchange

import (
	"fmt"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwt"
)

// PresentationRequestType represents wrappers for Presentation Definitions submitted as requests
// https://identity.foundation/presentation-exchange/#presentation-request
type PresentationRequestType string

const (
	// JWTRequest is a wrapper for a `presentation_definition` inside a signed JWT
	JWTRequest PresentationRequestType = "jwt"

	// JWT key values

	PresentationDefinitionKey string = "presentation_definition"
)

// BuildPresentationRequest https://identity.foundation/presentation-exchange/#presentation-request
// used for transmitting a Presentation Definition from a holder to a verifier. Target is who the request is intended for.
// TODO(gabe) expand to other presentation types and signers https://github.com/TBD54566975/did-sdk/issues/57
func BuildPresentationRequest(signer cryptosuite.Signer, pt PresentationRequestType, def PresentationDefinition, target string) ([]byte, error) {
	if !IsSupportedPresentationRequestType(pt) {
		return nil, fmt.Errorf("unsupported presentation request type: %s", pt)
	}
	switch pt {
	case JWTRequest:
		jwkSigner, ok := signer.(*cryptosuite.JSONWebKeySigner)
		if !ok {
			return nil, fmt.Errorf("signer not valid for request type: %s", pt)
		}
		return BuildJWTPresentationRequest(*jwkSigner, def, target)
	default:
		return nil, fmt.Errorf("presentation request type <%s> is not implemented", pt)
	}
}

// BuildJWTPresentationRequest builds a JWT representation of a presentation request
func BuildJWTPresentationRequest(signer cryptosuite.JSONWebKeySigner, def PresentationDefinition, target string) ([]byte, error) {
	jwtValues := map[string]interface{}{
		jwt.JwtIDKey:              uuid.New().String(),
		jwt.IssuerKey:             signer.GetKeyID(),
		jwt.AudienceKey:           target,
		PresentationDefinitionKey: def,
	}
	return signer.SignGenericJWT(jwtValues)
}

func IsSupportedPresentationRequestType(rt PresentationRequestType) bool {
	supported := GetSupportedPresentationRequestTypes()
	for _, t := range supported {
		if rt == t {
			return true
		}
	}
	return false
}

func GetSupportedPresentationRequestTypes() []PresentationRequestType {
	return []PresentationRequestType{JWTRequest}
}
