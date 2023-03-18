package ion

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
)

const (
	maxIDLength   = 50
	maxTypeLength = 30
)

// NewCreateRequest creates a new create request https://identity.foundation/sidetree/spec/#create
func NewCreateRequest(recoveryKey, updateKey crypto.PublicKeyJWK, document Document) (*CreateRequest, error) {
	// prepare delta
	patches := []Patch{
		{
			ReplaceAction: &ReplaceAction{
				Action:   Replace,
				Document: document,
			},
		},
	}
	_, updateCommitment, err := CommitJWK(updateKey)
	if err != nil {
		return nil, err
	}
	delta := Delta{
		UpdateCommitment: updateCommitment,
		Patches:          patches,
	}

	// prepare suffix data
	deltaCanonical, err := CanonicalizeAny(delta)
	if err != nil {
		return nil, err
	}
	deltaHash, err := Multihash(deltaCanonical)
	if err != nil {
		return nil, err
	}
	_, recoveryCommitment, err := CommitJWK(recoveryKey)
	if err != nil {
		return nil, err
	}
	suffixData := SuffixData{
		DeltaHash:          string(deltaHash),
		RecoveryCommitment: recoveryCommitment,
	}

	return &CreateRequest{
		Type:       Create,
		SuffixData: suffixData,
		Delta:      delta,
	}, nil
}

// NewDeactivateRequest creates a new deactivate request https://identity.foundation/sidetree/spec/#deactivate
func NewDeactivateRequest(didSuffix string, recoveryKey crypto.PublicKeyJWK, signer crypto.JWTSigner) (*DeactivateRequest, error) {
	// prepare reveal value
	revealValue, _, err := CommitJWK(recoveryKey)
	if err != nil {
		return nil, err
	}

	// prepare signed data
	toBeSigned := struct {
		DIDSuffix   string              `json:"didSuffix"`
		RecoveryKey crypto.PublicKeyJWK `json:"recoveryKey"`
	}{
		DIDSuffix:   didSuffix,
		RecoveryKey: recoveryKey,
	}
	toBeSignedBytes, err := json.Marshal(toBeSigned)
	if err != nil {
		return nil, err
	}
	var toBeSignedJSON map[string]any
	if err = json.Unmarshal(toBeSignedBytes, &toBeSignedJSON); err != nil {
		return nil, err
	}
	signedJWT, err := signer.SignJWT(toBeSignedJSON)
	if err != nil {
		return nil, err
	}
	return &DeactivateRequest{
		Type:        Deactivate,
		DIDSuffix:   didSuffix,
		RevealValue: revealValue,
		SignedData:  string(signedJWT),
	}, nil
}

// NewRecoverRequest creates a new recover request https://identity.foundation/sidetree/spec/#recover
func NewRecoverRequest(didSuffix string, recoveryKey, nextRecoveryKey, nextUpdateKey crypto.PublicKeyJWK, document Document, signer crypto.JWTSigner) (*RecoverRequest, error) { //revive:disable-line:argument-limit
	// prepare reveal value
	revealValue, _, err := CommitJWK(recoveryKey)
	if err != nil {
		return nil, err
	}

	// prepare delta
	patches := []Patch{
		{
			ReplaceAction: &ReplaceAction{
				Action:   Replace,
				Document: document,
			},
		},
	}

	_, updateCommitment, err := CommitJWK(nextUpdateKey)
	if err != nil {
		return nil, err
	}

	delta := Delta{
		UpdateCommitment: updateCommitment,
		Patches:          patches,
	}

	// prepare signed data
	deltaCanonical, err := CanonicalizeAny(delta)
	if err != nil {
		return nil, err
	}
	deltaHash, err := Multihash(deltaCanonical)
	if err != nil {
		return nil, err
	}
	_, recoveryCommitment, err := CommitJWK(nextRecoveryKey)
	if err != nil {
		return nil, err
	}

	toBeSigned := struct {
		RecoveryCommitment string              `json:"recoveryCommitment"`
		RecoveryKey        crypto.PublicKeyJWK `json:"recoveryKey"`
		DeltaHash          string              `json:"deltaHash"`
	}{
		RecoveryCommitment: recoveryCommitment,
		RecoveryKey:        recoveryKey,
		DeltaHash:          string(deltaHash),
	}
	toBeSignedBytes, err := json.Marshal(toBeSigned)
	if err != nil {
		return nil, err
	}
	var toBeSignedJSON map[string]any
	if err = json.Unmarshal(toBeSignedBytes, &toBeSignedJSON); err != nil {
		return nil, err
	}
	signedJWT, err := signer.SignJWT(toBeSignedJSON)
	if err != nil {
		return nil, err
	}

	return &RecoverRequest{
		Type:        Recover,
		DIDSuffix:   didSuffix,
		RevealValue: revealValue,
		Delta:       delta,
		SignedData:  string(signedJWT),
	}, nil
}

type StateChange struct {
	ServicesToAdd        []Service
	ServiceIDsToRemove   []string
	PublicKeysToAdd      []PublicKey
	PublicKeyIDsToRemove []string
}

func (s StateChange) IsValid() error {
	// check if services are valid
	// build index of services to make sure IDs are unique
	services := make(map[string]Service)
	for _, service := range s.ServicesToAdd {
		if _, ok := services[service.ID]; ok {
			return fmt.Errorf("service %s duplicated", service.ID)
		}

		if len(service.ID) > maxIDLength {
			return fmt.Errorf("service<%s> id is too long", service.ID)
		}

		// make sure service is valid if it's not a dupe
		if len(service.Type) > maxTypeLength {
			return fmt.Errorf("service<%s> type %s is too long", service.ID, service.Type)
		}

		services[service.ID] = service
	}

	// check if public keys are valid
	// build index of public keys to add
	publicKeys := make(map[string]PublicKey)
	for _, publicKey := range s.PublicKeysToAdd {
		if _, ok := publicKeys[publicKey.ID]; ok {
			return fmt.Errorf("public key<%s> is duplicated", publicKey.ID)
		}

		if len(publicKey.ID) > maxIDLength {
			return fmt.Errorf("public key<%s> id is too long", publicKey.ID)
		}

		// make sure public key is valid if it's not a dupe
		if len(publicKey.Type) > maxTypeLength {
			return fmt.Errorf("public key<%s> type %s is too long", publicKey.ID, publicKey.Type)
		}

		publicKeys[publicKey.ID] = publicKey
	}

	// check if services to remove are valid
	for _, serviceID := range s.ServiceIDsToRemove {
		if _, ok := services[serviceID]; !ok {
			return fmt.Errorf("service<%s> added and removed in same request", serviceID)
		}

		if len(serviceID) > maxIDLength {
			return fmt.Errorf("service<%s> id is too long", serviceID)
		}
	}

	// check if public keys to remove are valid
	for _, publicKeyID := range s.PublicKeyIDsToRemove {
		if _, ok := publicKeys[publicKeyID]; !ok {
			return fmt.Errorf("public key<%s> added and removed in same request", publicKeyID)
		}

		if len(publicKeyID) > maxIDLength {
			return fmt.Errorf("public key<%s> id is too long", publicKeyID)
		}
	}
	return nil
}

// NewUpdateRequest creates a new update request https://identity.foundation/sidetree/spec/#update
func NewUpdateRequest(didSuffix string, updateKey, nextUpdateKey crypto.PublicKeyJWK, signer crypto.JWTSigner, stateChange StateChange) (*UpdateRequest, error) {
	if err := stateChange.IsValid(); err != nil {
		return nil, err
	}

	// construct update patches
	var patches []Patch

	// services to add
	if len(stateChange.ServicesToAdd) > 0 {
		addServicesPatch := Patch{
			AddServicesAction: &AddServicesAction{
				Action:   AddServices,
				Services: stateChange.ServicesToAdd,
			},
		}
		patches = append(patches, addServicesPatch)
	}

	// services to remove
	if len(stateChange.ServiceIDsToRemove) > 0 {
		removeServicesPatch := Patch{
			RemoveServicesAction: &RemoveServicesAction{
				Action: RemoveServices,
				IDs:    stateChange.ServiceIDsToRemove,
			},
		}
		patches = append(patches, removeServicesPatch)
	}

	// public keys to add
	if len(stateChange.PublicKeysToAdd) > 0 {
		addPublicKeysPatch := Patch{
			AddPublicKeysAction: &AddPublicKeysAction{
				Action:     AddPublicKeys,
				PublicKeys: stateChange.PublicKeysToAdd,
			},
		}
		patches = append(patches, addPublicKeysPatch)
	}

	// public keys to remove
	if len(stateChange.PublicKeyIDsToRemove) > 0 {
		removePublicKeysPatch := Patch{
			RemovePublicKeysAction: &RemovePublicKeysAction{
				Action: RemovePublicKeys,
				IDs:    stateChange.PublicKeyIDsToRemove,
			},
		}
		patches = append(patches, removePublicKeysPatch)
	}

	// prepare reveal value
	revealValue, _, err := CommitJWK(updateKey)
	if err != nil {
		return nil, err
	}

	// prepare delta
	_, nextUpdateCommitment, err := CommitJWK(nextUpdateKey)
	if err != nil {
		return nil, err
	}
	delta := Delta{
		UpdateCommitment: nextUpdateCommitment,
		Patches:          patches,
	}
	deltaCanonical, err := CanonicalizeAny(delta)
	if err != nil {
		return nil, err
	}
	deltaHash, err := Multihash(deltaCanonical)
	if err != nil {
		return nil, err
	}

	// prepare signed data
	toBeSigned := struct {
		UpdateKey crypto.PublicKeyJWK `json:"updateKey"`
		DeltaHash string              `json:"deltaHash"`
	}{
		UpdateKey: updateKey,
		DeltaHash: string(deltaHash),
	}
	toBeSignedBytes, err := json.Marshal(toBeSigned)
	if err != nil {
		return nil, err
	}
	var toBeSignedJSON map[string]any
	if err = json.Unmarshal(toBeSignedBytes, &toBeSignedJSON); err != nil {
		return nil, err
	}
	signedJWT, err := signer.SignJWT(toBeSignedJSON)
	if err != nil {
		return nil, err
	}

	return &UpdateRequest{
		Type:        Update,
		DIDSuffix:   didSuffix,
		RevealValue: revealValue,
		Delta:       delta,
		SignedData:  string(signedJWT),
	}, nil
}
