package ion

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
)

// object models

type Document struct {
	PublicKeys []PublicKey `json:"publicKeys,omitempty"`
	Services   []Service   `json:"services,omitempty"`
}

func (d Document) IsEmpty() bool {
	return len(d.PublicKeys) == 0 && len(d.Services) == 0
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

type AnchorOperation interface {
	GetType() OperationType
}

type CreateRequest struct {
	Type       OperationType `json:"type,omitempty"`
	SuffixData SuffixData    `json:"suffixData,omitempty"`
	Delta      Delta         `json:"delta,omitempty"`
}

func (CreateRequest) GetType() OperationType {
	return Create
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

func (UpdateRequest) GetType() OperationType {
	return Update
}

// UpdateSignedDataObject https://identity.foundation/sidetree/spec/#update-signed-data-object
type UpdateSignedDataObject struct {
	UpdateKey crypto.PublicKeyJWK `json:"updateKey,omitempty"`
	DeltaHash string              `json:"deltaHash,omitempty"`
}

type Delta struct {
	Patches          []any  `json:"patches,omitempty"` //revive:disable-line
	UpdateCommitment string `json:"updateCommitment,omitempty"`
}

func NewDelta(updateCommitment string) Delta {
	return Delta{
		Patches:          make([]any, 0),
		UpdateCommitment: updateCommitment,
	}
}

func (d *Delta) GetPatches() []any {
	return d.Patches
}

func (d *Delta) AddAddServicesAction(patch AddServicesAction) {
	d.Patches = append(d.Patches, patch)
}

func (d *Delta) AddRemoveServicesAction(patch RemoveServicesAction) {
	d.Patches = append(d.Patches, patch)
}

func (d *Delta) AddAddPublicKeysAction(patch AddPublicKeysAction) {
	d.Patches = append(d.Patches, patch)
}

func (d *Delta) AddRemovePublicKeysAction(patch RemovePublicKeysAction) {
	d.Patches = append(d.Patches, patch)
}

func (d *Delta) AddReplaceAction(patch ReplaceAction) {
	d.Patches = append(d.Patches, patch)
}

type DeactivateRequest struct {
	Type        OperationType `json:"type,omitempty"`
	DIDSuffix   string        `json:"didSuffix,omitempty"`
	RevealValue string        `json:"revealValue,omitempty"`
	SignedData  string        `json:"signedData,omitempty"`
}

func (DeactivateRequest) GetType() OperationType {
	return Deactivate
}

// DeactivateSignedDataObject https://identity.foundation/sidetree/spec/#deactivate-signed-data-object
type DeactivateSignedDataObject struct {
	DIDSuffix   string              `json:"didSuffix,omitempty"`
	RecoveryKey crypto.PublicKeyJWK `json:"recoveryKey,omitempty"`
}

type RecoverRequest struct {
	Type        OperationType `json:"type,omitempty"`
	DIDSuffix   string        `json:"didSuffix,omitempty"`
	RevealValue string        `json:"revealValue,omitempty"`
	Delta       Delta         `json:"delta,omitempty"`
	SignedData  string        `json:"signedData,omitempty"`
}

func (RecoverRequest) GetType() OperationType {
	return Recover
}

// RecoverySignedDataObject https://identity.foundation/sidetree/spec/#recovery-signed-data-object
type RecoverySignedDataObject struct {
	RecoveryCommitment string              `json:"recoveryCommitment,omitempty"`
	RecoveryKey        crypto.PublicKeyJWK `json:"recoveryKey,omitempty"`
	DeltaHash          string              `json:"deltaHash,omitempty"`
	AnchorOrigin       string              `json:"anchorOrigin,omitempty"`
}
