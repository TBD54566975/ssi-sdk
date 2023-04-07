package exchange

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
)

// PresentationRequestType represents wrappers for Presentation Definitions submitted as requests
// https://identity.foundation/presentation-exchange/#presentation-request
type PresentationRequestType string

const (
	// JWTRequest is a wrapper for a `presentation_definition` inside a signed JWT
	JWTRequest PresentationRequestType = "jwt"

	// JWT key values

	PresentationDefinitionKey string = "presentation_definition"

	// Presentation Request Option types

	TargetOption PresentationRequestOptionType = "target"
)

type PresentationRequestOptionType string

type PresentationRequestOption struct {
	Type  PresentationRequestOptionType
	Value any
}

// BuildPresentationRequest https://identity.foundation/presentation-exchange/#presentation-request
// used for transmitting a Presentation Definition from a holder to a verifier. Target is who the request is intended for.
// TODO(gabe) expand to other presentation types and signers https://github.com/TBD54566975/ssi-sdk/issues/57
func BuildPresentationRequest(signer any, pt PresentationRequestType, def PresentationDefinition, opts ...PresentationRequestOption) ([]byte, error) {
	if signer == nil {
		return nil, fmt.Errorf("cannot build presentation request with nil signer")
	}

	// process options
	if len(opts) > 1 {
		return nil, fmt.Errorf("only one option supported")
	}
	var target string
	if len(opts) == 1 {
		opt := opts[0]
		if opt.Type != TargetOption {
			return nil, fmt.Errorf("unsupported option type: %s", opt.Type)
		}
		var ok bool
		target, ok = opt.Value.(string)
		if !ok {
			return nil, fmt.Errorf("target option value must be a string")
		}
	}

	if !IsSupportedPresentationRequestType(pt) {
		return nil, fmt.Errorf("unsupported presentation request type: %s", pt)
	}
	switch pt {
	case JWTRequest:
		jwtSigner, ok := signer.(crypto.JWTSigner)
		if !ok {
			return nil, errors.New("signer is not a JWTSigner")
		}
		return BuildJWTPresentationRequest(jwtSigner, def, target)
	default:
		return nil, fmt.Errorf("presentation request type <%s> is not implemented", pt)
	}
}

// BuildJWTPresentationRequest builds a JWT representation of a presentation request
func BuildJWTPresentationRequest(signer crypto.JWTSigner, def PresentationDefinition, target string) ([]byte, error) {
	jwtValues := map[string]any{
		jwt.JwtIDKey:              uuid.NewString(),
		jwt.IssuerKey:             signer.ID,
		jwt.AudienceKey:           target,
		PresentationDefinitionKey: def,
	}
	if target != "" {
		jwtValues[jwt.AudienceKey] = target
	}
	return signer.SignWithDefaults(jwtValues)
}

// VerifyPresentationRequest finds the correct verifier and parser for a given presentation request type,
// verifying the signature on the request, and returning the parsed Presentation Definition object.
func VerifyPresentationRequest(verifier crypto.JWTVerifier, pt PresentationRequestType, request []byte) (*PresentationDefinition, error) {
	err := fmt.Errorf("cannot verify unsupported presentation request type: %s", pt)
	if !IsSupportedPresentationRequestType(pt) {
		return nil, err
	}
	switch pt {
	case JWTRequest:
		return VerifyJWTPresentationRequest(verifier, request)
	default:
		return nil, err
	}
}

// VerifyJWTPresentationRequest verifies the signature on a JWT-based presentation request for a given verifier
// and then returns the parsed Presentation Definition object as a result.
func VerifyJWTPresentationRequest(verifier crypto.JWTVerifier, request []byte) (*PresentationDefinition, error) {
	parsed, err := verifier.VerifyAndParse(string(request))
	if err != nil {
		return nil, errors.Wrap(err, "could not verify and parse jwt presentation request")
	}
	presDefGeneric, ok := parsed.Get(PresentationDefinitionKey)
	if !ok {
		return nil, fmt.Errorf("presentation definition key<%s> not found in token", PresentationDefinitionKey)
	}
	presDefBytes, err := json.Marshal(presDefGeneric)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal token into bytes for presentation definition")
	}
	var def PresentationDefinition
	if err := json.Unmarshal(presDefBytes, &def); err != nil {
		return nil, errors.Wrap(err, "could not unmarshal token into presentation definition")
	}
	return &def, nil
}

// IsSupportedPresentationRequestType returns whether a given presentation request embed target is supported by this lib
func IsSupportedPresentationRequestType(rt PresentationRequestType) bool {
	supported := GetSupportedPresentationRequestTypes()
	for _, t := range supported {
		if rt == t {
			return true
		}
	}
	return false
}

// GetSupportedPresentationRequestTypes returns all supported presentation request embed targets
func GetSupportedPresentationRequestTypes() []PresentationRequestType {
	return []PresentationRequestType{JWTRequest}
}
