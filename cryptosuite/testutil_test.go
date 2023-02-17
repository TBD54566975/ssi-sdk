package cryptosuite

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
)

type TestCredential struct {
	Context           interface{}   `json:"@context" validate:"required"`
	ID                string        `json:"id,omitempty"`
	Type              interface{}   `json:"type" validate:"required"`
	Issuer            interface{}   `json:"issuer" validate:"required"`
	IssuanceDate      string        `json:"issuanceDate" validate:"required"`
	ExpirationDate    string        `json:"expirationDate,omitempty"`
	CredentialStatus  interface{}   `json:"credentialStatus,omitempty" validate:"omitempty,dive"`
	CredentialSubject interface{}   `json:"credentialSubject" validate:"required"`
	CredentialSchema  interface{}   `json:"credentialSchema,omitempty" validate:"omitempty,dive"`
	RefreshService    interface{}   `json:"refreshService,omitempty" validate:"omitempty,dive"`
	TermsOfUse        []interface{} `json:"termsOfUse,omitempty" validate:"omitempty,dive"`
	Evidence          []interface{} `json:"evidence,omitempty" validate:"omitempty,dive"`
	Proof             *crypto.Proof `json:"proof,omitempty"`
}

func (t *TestCredential) GetProof() *crypto.Proof {
	return t.Proof
}

func (t *TestCredential) SetProof(p *crypto.Proof) {
	t.Proof = p
}
