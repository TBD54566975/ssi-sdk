package ion

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// object models

type Document struct {
	PublicKeys []PublicKey   `json:"publicKeys,omitempty"`
	Services   []did.Service `json:"services,omitempty"`
}

func (d Document) IsEmpty() bool {
	return len(d.PublicKeys) == 0 && len(d.Services) == 0
}

type PublicKey struct {
	ID           string             `json:"id,omitempty"`
	Type         string             `json:"type,omitempty"`
	PublicKeyJWK jwx.PublicKeyJWK   `json:"publicKeyJwk,omitempty"`
	Purposes     []PublicKeyPurpose `json:"purposes,omitempty"`
}

// action models

// AddServicesAction https://identity.foundation/sidetree/spec/#add-services
type AddServicesAction struct {
	Action   PatchAction   `json:"action,omitempty"`
	Services []did.Service `json:"services,omitempty"`
}

func (a AddServicesAction) GetAction() PatchAction {
	return a.Action
}

// RemoveServicesAction https://identity.foundation/sidetree/spec/#remove-services
type RemoveServicesAction struct {
	Action PatchAction `json:"action,omitempty"`
	IDs    []string    `json:"ids,omitempty"`
}

func (a RemoveServicesAction) GetAction() PatchAction {
	return a.Action
}

// AddPublicKeysAction https://identity.foundation/sidetree/spec/#add-public-keys
type AddPublicKeysAction struct {
	Action     PatchAction `json:"action,omitempty"`
	PublicKeys []PublicKey `json:"publicKeys,omitempty"`
}

func (a AddPublicKeysAction) GetAction() PatchAction {
	return a.Action
}

// RemovePublicKeysAction https://identity.foundation/sidetree/spec/#add-public-keys
type RemovePublicKeysAction struct {
	Action PatchAction `json:"action,omitempty"`
	IDs    []string    `json:"ids,omitempty"`
}

func (a RemovePublicKeysAction) GetAction() PatchAction {
	return a.Action
}

// ReplaceAction https://identity.foundation/sidetree/spec/#replace
type ReplaceAction struct {
	Action   PatchAction `json:"action,omitempty"`
	Document Document    `json:"document,omitempty"`
}

func (a ReplaceAction) GetAction() PatchAction {
	return a.Action
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
	UpdateKey jwx.PublicKeyJWK `json:"updateKey,omitempty"`
	DeltaHash string           `json:"deltaHash,omitempty"`
}

type Delta struct {
	Patches          []Patch `json:"patches,omitempty"` //revive:disable-line
	UpdateCommitment string  `json:"updateCommitment,omitempty"`
}

func (d *Delta) UnmarshalJSON(data []byte) error {
	var deltaMap map[string]any
	if err := json.Unmarshal(data, &deltaMap); err != nil {
		return errors.Wrap(err, "unmarshalling patch to generic map")
	}
	updateCommitment, ok := deltaMap["updateCommitment"].(string)
	if !ok {
		return fmt.Errorf("no updateCommitment found in delta")
	}
	d.UpdateCommitment = updateCommitment
	allPatches, ok := deltaMap["patches"].([]any)
	if !ok {
		return fmt.Errorf("no patches found in delta")
	}
	var patches []Patch
	for _, patch := range allPatches {
		currPatch, ok := patch.(map[string]any)
		if !ok {
			return fmt.Errorf("patch is not a map")
		}
		action, ok := currPatch["action"]
		if !ok {
			return fmt.Errorf("patch has no action")
		}
		currPatchBytes, err := json.Marshal(currPatch)
		if err != nil {
			return errors.Wrap(err, "marshalling patch")
		}
		switch action {
		case Replace.String():
			var ra ReplaceAction
			if err := json.Unmarshal(currPatchBytes, &ra); err != nil {
				return errors.Wrap(err, "unmarshalling replace action")
			}
			patches = append(patches, ra)
		case AddPublicKeys.String():
			var apa AddPublicKeysAction
			if err := json.Unmarshal(currPatchBytes, &apa); err != nil {
				return errors.Wrap(err, "unmarshalling add public keys action")
			}
			patches = append(patches, apa)
		case RemovePublicKeys.String():
			var rpa RemovePublicKeysAction
			if err := json.Unmarshal(currPatchBytes, &rpa); err != nil {
				return errors.Wrap(err, "unmarshalling remove public keys action")
			}
			patches = append(patches, rpa)
		case AddServices.String():
			var asa AddServicesAction
			if err := json.Unmarshal(currPatchBytes, &asa); err != nil {
				return errors.Wrap(err, "unmarshalling add services action")
			}
			patches = append(patches, asa)
		case RemoveServices.String():
			var rsa RemoveServicesAction
			if err := json.Unmarshal(currPatchBytes, &rsa); err != nil {
				return errors.Wrap(err, "unmarshalling remove services action")
			}
			patches = append(patches, rsa)
		default:
			return fmt.Errorf("unknown patch action: %s", action)
		}
	}
	d.Patches = patches
	return nil
}

func NewDelta(updateCommitment string) Delta {
	return Delta{
		Patches:          make([]Patch, 0),
		UpdateCommitment: updateCommitment,
	}
}

func (d *Delta) GetPatches() []Patch {
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
	DIDSuffix   string           `json:"didSuffix,omitempty"`
	RecoveryKey jwx.PublicKeyJWK `json:"recoveryKey,omitempty"`
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
	RecoveryCommitment string           `json:"recoveryCommitment,omitempty"`
	RecoveryKey        jwx.PublicKeyJWK `json:"recoveryKey,omitempty"`
	DeltaHash          string           `json:"deltaHash,omitempty"`
	AnchorOrigin       string           `json:"anchorOrigin,omitempty"`
}
