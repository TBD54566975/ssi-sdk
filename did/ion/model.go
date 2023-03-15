package ion

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
)

// object models

type Document struct {
	PublicKeys []PublicKey
	Services   []Service
}

// Service declaration in a DID Document
type Service struct {
	ID              string
	Type            string
	ServiceEndpoint any
}

type PublicKey struct {
	ID           string
	Type         string
	PublicKeyJWK crypto.PublicKeyJWK
	Purposes     []PublicKeyPurpose
}

// action models

// AddServicesAction https://identity.foundation/sidetree/spec/#add-services
type AddServicesAction struct {
	Action   PatchAction
	Services []Service
}

// RemoveServicesAction https://identity.foundation/sidetree/spec/#remove-services
type RemoveServicesAction struct {
	Action PatchAction
	IDs    []string
}

// AddPublicKeysAction https://identity.foundation/sidetree/spec/#add-public-keys
type AddPublicKeysAction struct {
	Action     PatchAction
	PublicKeys []PublicKey
}

// RemovePublicKeysAction https://identity.foundation/sidetree/spec/#add-public-keys
type RemovePublicKeysAction struct {
	Action PatchAction
	IDs    []string
}

// ReplaceAction https://identity.foundation/sidetree/spec/#replace
type ReplaceAction struct {
	Action   PatchAction `json:"action" validate:"required"`
	Document Document    `json:"document" validate:"required"`
}

// request models

// Patch Only one of these values should be set
type Patch struct {
	*AddServicesAction
	*AddPublicKeysAction
	*RemoveServicesAction
	*RemovePublicKeysAction
	*ReplaceAction
}

type CreateRequest struct {
	Type       OperationType
	SuffixData SuffixData
	Delta      Delta
}

type SuffixData struct {
	DeltaHash          string
	RecoveryCommitment string
}

type UpdateRequest struct {
	Type        OperationType
	DIDSuffix   string
	RevealValue string
	Delta       Delta
}

type Delta struct {
	UpdateCommitment string
	Patches          []Patch
}

type DeactivateRequest struct {
	Type        OperationType
	DIDSuffix   string
	RevealValue string
	SignedData  string
}

type RecoverRequest struct {
	Type        OperationType
	DIDSuffix   string
	RevealValue string
	Delta       Delta
	SignedData  string
}
