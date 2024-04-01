package credential

import (
	"reflect"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/util"
)

// VerifiableCredential is the verifiable credential model outlined in the
// vc-data-model spec https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#basic-concepts
type VerifiableCredential struct {
	// Either a string or set of strings
	Context any    `json:"@context" validate:"required"`
	ID      string `json:"id,omitempty"`
	// Either a string or a set of strings https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#types
	Type any `json:"type" validate:"required"`
	// either a URI or an object containing an `id` property.
	Issuer any `json:"issuer,omitempty" validate:"required"`
	// https://www.w3.org/TR/xmlschema11-2/#dateTimes
	IssuanceDate     string `json:"issuanceDate,omitempty" validate:"required"`
	ExpirationDate   string `json:"expirationDate,omitempty"`
	CredentialStatus any    `json:"credentialStatus,omitempty" validate:"omitempty"`
	// This is where the subject's ID *may* be present
	CredentialSubject CredentialSubject `json:"credentialSubject" validate:"required"`
	CredentialSchema  *CredentialSchema `json:"credentialSchema,omitempty" validate:"omitempty"`
	RefreshService    *RefreshService   `json:"refreshService,omitempty" validate:"omitempty"`
	TermsOfUse        []TermsOfUse      `json:"termsOfUse,omitempty" validate:"omitempty,dive"`
	Evidence          []any             `json:"evidence,omitempty" validate:"omitempty"`
	// For embedded proof support
	// Proof is a digital signature over a credential https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#proofs-signatures
	Proof *crypto.Proof `json:"proof,omitempty"`
}

func (v *VerifiableCredential) GetProof() *crypto.Proof {
	return v.Proof
}

func (v *VerifiableCredential) SetProof(p *crypto.Proof) {
	v.Proof = p
}

// DefaultCredentialStatus https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#status
type DefaultCredentialStatus struct {
	ID   string `json:"id" validate:"required"`
	Type string `json:"type" validate:"required"`
}

type CredentialSubject map[string]any

func (cs CredentialSubject) GetID() string {
	id := ""
	if gotID, ok := cs[VerifiableCredentialIDProperty]; ok {
		id = gotID.(string)
	}
	return id
}

func (cs CredentialSubject) GetJSONSchema() map[string]any {
	var schema map[string]any
	if gotSchema, ok := cs[VerifiableCredentialJSONSchemaProperty]; ok {
		schema, ok = gotSchema.(map[string]any)
		if !ok {
			return nil
		}
	}
	return schema
}

type CredentialSchema struct {
	ID        string `json:"id" validate:"required"`
	Type      string `json:"type" validate:"required"`
	DigestSRI string `json:"digestSRI,omitempty"`
}

type RefreshService struct {
	ID   string `json:"id" validate:"required"`
	Type string `json:"type" validate:"required"`
}

// TermsOfUse In the current version of the specification TOU isn't well-defined; these fields are subject to change
// https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#terms-of-use
type TermsOfUse struct {
	Type        string        `json:"type,omitempty"`
	ID          string        `json:"id,omitempty"`
	Profile     string        `json:"profile,omitempty"`
	Prohibition []Prohibition `json:"prohibition,omitempty"`
}

type Prohibition struct {
	Assigner string   `json:"assigner,omitempty"`
	Assignee string   `json:"assignee,omitempty"`
	Target   string   `json:"target,omitempty"`
	Action   []string `json:"action,omitempty"`
}

func (v *VerifiableCredential) IsEmpty() bool {
	if v == nil {
		return true
	}
	return reflect.DeepEqual(v, &VerifiableCredential{})
}

func (v *VerifiableCredential) IsValid() error {
	return util.NewValidator().Struct(v)
}

func (v *VerifiableCredential) IssuerID() string {
	switch typedIssuer := v.Issuer.(type) {
	case string:
		return typedIssuer
	case []string:
		return typedIssuer[0]
	case map[string]any:
		idValue := typedIssuer["id"]
		return idValue.(string)
	}
	return ""
}

// VerifiablePresentation https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#presentations-0
type VerifiablePresentation struct {
	// Either a string or set of strings
	Context any    `json:"@context,omitempty"`
	ID      string `json:"id,omitempty"`
	Holder  string `json:"holder,omitempty"`
	Type    any    `json:"type" validate:"required"`
	// an optional field as a part of https://identity.foundation/presentation-exchange/#embed-targets
	PresentationSubmission any `json:"presentation_submission,omitempty"`
	// Verifiable credential could be our object model, a JWT, or any other valid credential representation
	VerifiableCredential []any         `json:"verifiableCredential,omitempty"`
	Proof                *crypto.Proof `json:"proof,omitempty"`
}

func (v *VerifiablePresentation) IsEmpty() bool {
	if v == nil {
		return true
	}
	return reflect.DeepEqual(v, &VerifiablePresentation{})
}

func (v *VerifiablePresentation) IsValid() error {
	return util.NewValidator().Struct(v)
}

func (v *VerifiablePresentation) GetProof() *crypto.Proof {
	return v.Proof
}

func (v *VerifiablePresentation) SetProof(p *crypto.Proof) {
	v.Proof = p
}
