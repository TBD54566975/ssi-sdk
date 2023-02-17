package cryptosuite

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
)

type TestCredential struct {
	Context           any           `json:"@context" validate:"required"`
	ID                string        `json:"id,omitempty"`
	Type              any           `json:"type" validate:"required"`
	Issuer            any           `json:"issuer" validate:"required"`
	IssuanceDate      string        `json:"issuanceDate" validate:"required"`
	ExpirationDate    string        `json:"expirationDate,omitempty"`
	CredentialStatus  any           `json:"credentialStatus,omitempty" validate:"omitempty,dive"`
	CredentialSubject any           `json:"credentialSubject" validate:"required"`
	CredentialSchema  any           `json:"credentialSchema,omitempty" validate:"omitempty,dive"`
	RefreshService    any           `json:"refreshService,omitempty" validate:"omitempty,dive"`
	TermsOfUse        []any         `json:"termsOfUse,omitempty" validate:"omitempty,dive"`
	Evidence          []any         `json:"evidence,omitempty" validate:"omitempty,dive"`
	Proof             *crypto.Proof `json:"proof,omitempty"`
}

func (t *TestCredential) GetProof() *crypto.Proof {
	return t.Proof
}

func (t *TestCredential) SetProof(p *crypto.Proof) {
	t.Proof = p
}
