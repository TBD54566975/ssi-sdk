package vc

import (
	"reflect"

	"github.com/TBD54566975/did-sdk/cryptosuite"

	"github.com/TBD54566975/did-sdk/util"
)

// VerifiableCredential is the known_schemas model outlined in the
// vc known_schemas model spec https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#basic-concepts
type VerifiableCredential struct {
	// Either a string or set of strings
	Context interface{} `json:"@context" validate:"required"`
	ID      string      `json:"id,omitempty"`
	// Either a string or a set of strings https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#types
	Type interface{} `json:"type" validate:"required"`
	// either a URI or an object containing an `id` property.
	Issuer interface{} `json:"issuer" validate:"required"`
	// https://www.w3.org/TR/xmlschema11-2/#dateTimes
	IssuanceDate     string            `json:"issuanceDate" validate:"required"`
	ExpirationDate   string            `json:"expirationDate,omitempty"`
	CredentialStatus *CredentialStatus `json:"credentialStatus,omitempty" validate:"omitempty,dive"`
	// This is where the subject's ID *may* be present
	CredentialSubject CredentialSubject `json:"credentialSubject" validate:"required"`
	CredentialSchema  *CredentialSchema `json:"credentialSchema,omitempty" validate:"omitempty,dive"`
	RefreshService    *RefreshService   `json:"refreshService,omitempty" validate:"omitempty,dive"`
	TermsOfUse        []TermsOfUse      `json:"termsOfUse,omitempty" validate:"omitempty,dive"`
	Evidence          []interface{}     `json:"evidence,omitempty" validate:"omitempty,dive"`
	// For embedded proof support
	// Proof is a digital signature over a credential https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#proofs-signatures
	Proof *cryptosuite.Proof `json:"proof,omitempty"`
}

func (v *VerifiableCredential) GetProof() *cryptosuite.Proof {
	return v.Proof
}

func (v *VerifiableCredential) SetProof(p *cryptosuite.Proof) {
	v.Proof = p
}

// CredentialStatus https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#status
type CredentialStatus struct {
	ID   string `json:"id" validate:"required"`
	Type string `json:"type" validate:"required"`
}

type CredentialSubject map[string]interface{}

func (cs CredentialSubject) GetID() string {
	id := ""
	if gotID, ok := cs[VerifiableCredentialIDProperty]; ok {
		id = gotID.(string)
	}
	return id
}

type CredentialSchema struct {
	ID   string `json:"id" validate:"required"`
	Type string `json:"type" validate:"required"`
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

// VerifiablePresentation https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#presentations-0
type VerifiablePresentation struct {
	// Either a string or set of strings
	Context              interface{}            `json:"@context"`
	ID                   string                 `json:"id,omitempty"`
	Type                 interface{}            `json:"type" validate:"required"`
	VerifiableCredential []VerifiableCredential `json:"verifiableCredential,omitempty" validate:"omitempty,dive"`
	Proof                interface{}            `json:"proof,omitempty"`
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
