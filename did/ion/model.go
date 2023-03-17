package ion

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
)

// object models

type Document struct {
	PublicKeys []PublicKey `json:"publicKeys,omitempty"`
	Services   []Service   `json:"services,omitempty"`
}

// Service declaration in a DID Document
type Service struct {
	ID              string `json:"id,omitempty"`
	Type            string `json:"type,omitempty"`
	ServiceEndpoint any    `json:"serviceEndpoint,omitempty"`
}

type PublicKey struct {
	ID           string              `json:"id,omitempty"`
	Type         string              `json:"type,omitempty"`
	PublicKeyJWK crypto.PublicKeyJWK `json:"publicKeyJwk,omitempty"`
	Purposes     []PublicKeyPurpose  `json:"purposes,omitempty"`
}

// action models

// AddServicesAction https://identity.foundation/sidetree/spec/#add-services
type AddServicesAction struct {
	Action   PatchAction `json:"action,omitempty"`
	Services []Service   `json:"services,omitempty"`
}

// RemoveServicesAction https://identity.foundation/sidetree/spec/#remove-services
type RemoveServicesAction struct {
	Action PatchAction `json:"action,omitempty"`
	IDs    []string    `json:"ids,omitempty"`
}

// AddPublicKeysAction https://identity.foundation/sidetree/spec/#add-public-keys
type AddPublicKeysAction struct {
	Action     PatchAction `json:"action,omitempty"`
	PublicKeys []PublicKey `json:"publicKeys,omitempty"`
}

// RemovePublicKeysAction https://identity.foundation/sidetree/spec/#add-public-keys
type RemovePublicKeysAction struct {
	Action PatchAction `json:"action,omitempty"`
	IDs    []string    `json:"ids,omitempty"`
}

// ReplaceAction https://identity.foundation/sidetree/spec/#replace
type ReplaceAction struct {
	Action   PatchAction `json:"action,omitempty"`
	Document Document    `json:"document,omitempty"`
}

// request models

// Patch Only one of these values should be set
// type Patch struct {
// 	*AddServicesAction
// 	*AddPublicKeysAction
// 	*RemoveServicesAction
// 	*RemovePublicKeysAction
// 	*ReplaceAction
// }

type CreateRequest struct {
	Type       OperationType `json:"type,omitempty"`
	SuffixData SuffixData    `json:"suffixData,omitempty"`
	Delta      Delta         `json:"delta,omitempty"`
}

type SuffixData struct {
	DeltaHash          string `json:"deltaHash,omitempty"`
	RecoveryCommitment string `json:"recoveryCommitment,omitempty"`
}

type UpdateRequest struct {
	Type        OperationType `json:"type,omitempty"`
	DIDSuffix   string        `json:"didSuffix,omitempty"`
	RevealValue string        `json:"revealValue,omitempty"`
	Delta       Delta         `json:"delta,omitempty"`
	SignedData  string        `json:"signedData,omitempty"`
}

type Delta struct {
	Patches          []any  `json:"patches,omitempty"`
	UpdateCommitment string `json:"updateCommitment,omitempty"`
}

type DeactivateRequest struct {
	Type        OperationType `json:"type,omitempty"`
	DIDSuffix   string        `json:"didSuffix,omitempty"`
	RevealValue string        `json:"revealValue,omitempty"`
	SignedData  string        `json:"signedData,omitempty"`
}

type RecoverRequest struct {
	Type        OperationType `json:"type,omitempty"`
	DIDSuffix   string        `json:"didSuffix,omitempty"`
	RevealValue string        `json:"revealValue,omitempty"`
	Delta       Delta         `json:"delta,omitempty"`
	SignedData  string        `json:"signedData,omitempty"`
}
