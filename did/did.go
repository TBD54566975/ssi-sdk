package did

import (
	"github.com/TBD54566975/did-sdk/util"
)

// DIDDocument is a representation of the did core specification https://www.w3.org/TR/did-core
// TODO(gabe) enforce validation of DID syntax https://www.w3.org/TR/did-core/#did-syntax
type DIDDocument struct {
	Context interface{} `json:"@context,omitempty"`
	// As per https://www.w3.org/TR/did-core/#did-subject intermediate representations of DID Documents do not
	// require an ID property. The provided test vectors demonstrate IRs. As such, the property is optional.
	ID                   string                  `json:"id,omitempty"`
	Controller           string                  `json:"controller,omitempty"`
	AlsoKnownAs          string                  `json:"alsoKnownAs,omitempty"`
	VerificationMethod   []VerificationMethod    `json:"verificationMethod,omitempty" validate:"dive"`
	Authentication       []VerificationMethodSet `json:"authentication,omitempty" validate:"dive"`
	AssertionMethod      []VerificationMethodSet `json:"assertionMethod,omitempty" validate:"dive"`
	KeyAgreement         []VerificationMethodSet `json:"keyAgreement,omitempty" validate:"dive"`
	CapabilityInvocation []VerificationMethodSet `json:"capabilityInvocation,omitempty" validate:"dive"`
	CapabilityDelegation []VerificationMethodSet `json:"capabilityDelegation,omitempty" validate:"dive"`
	Services             []Service               `json:"service,omitempty" validate:"dive"`
}

type VerificationMethod struct {
	ID              string `json:"id" validate:"required"`
	Type            string `json:"type" validate:"required"`
	Controller      string `json:"controller" validate:"required"`
	PublicKeyBase58 string `json:"publicKeyBase58,omitempty"`
	// must conform to https://datatracker.ietf.org/doc/html/rfc7517
	PublicKeyJWK *PublicKeyJWK `json:"publicKeyJwk,omitempty" validate:"dive"`
	// https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-03
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
}

// VerificationMethodSet is a union type supporting the `authentication`, `assertionMethod`, `keyAgreement`,
// `capabilityInvocation`, and `capabilityDelegation` types.
// A set of one or more verification methods. Each verification method MAY be embedded or referenced.
// TODO(gabe) consider changing this to a custom unmarshaler https://stackoverflow.com/a/28016508
type VerificationMethodSet interface{}

// PublicKeyJWK complies with RFC7517 https://datatracker.ietf.org/doc/html/rfc7517
type PublicKeyJWK struct {
	KTY    string `json:"kty" validate:"required"`
	CRV    string `json:"crv,omitempty"`
	X      string `json:"x,omitempty"`
	Y      string `json:"y,omitempty"`
	N      string `json:"n,omitempty"`
	E      string `json:"e,omitempty"`
	Use    string `json:"use,omitempty"`
	KeyOps string `json:"key_ops,omitempty"`
	Alg    string `json:"alg,omitempty"`
	KID    string `json:"kid,omitempty"`
}

// Service is a property compliant with the did-core spec https://www.w3.org/TR/did-core/#services
type Service struct {
	ID   string `json:"id" validate:"required"`
	Type string `json:"type" validate:"required"`
	// A string, map, or set composed of one or more strings and/or maps
	// All string values must be valid URIs
	ServiceEndpoint interface{} `json:"serviceEndpoint" validate:"required"`
}

func (d *DIDDocument) IsEmpty() bool {
	return false
}

func (d *DIDDocument) IsValid() error {
	return util.GetValidator().Struct(d)
}
