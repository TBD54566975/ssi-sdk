package ion

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/pkg/errors"
)

const (
	maxIDLength          = 50
	maxServiceTypeLength = 30
)

// NewCreateRequest creates a new create request https://identity.foundation/sidetree/spec/#create
func NewCreateRequest(recoveryKey, updateKey crypto.PublicKeyJWK, document Document) (*CreateRequest, error) {
	// prepare delta
	replaceActionPatch := ReplaceAction{
		Action:   Replace,
		Document: document,
	}
	_, updateCommitment, err := Commit(updateKey)
	if err != nil {
		return nil, err
	}
	delta := NewDelta(updateCommitment)
	delta.AddReplaceAction(replaceActionPatch)

	// prepare suffix data
	deltaCanonical, err := CanonicalizeAny(delta)
	if err != nil {
		return nil, err
	}
	deltaHash, err := HashEncode(deltaCanonical)
	if err != nil {
		return nil, err
	}
	_, recoveryCommitment, err := Commit(recoveryKey)
	if err != nil {
		return nil, err
	}
	suffixData := SuffixData{
		DeltaHash:          deltaHash,
		RecoveryCommitment: recoveryCommitment,
	}

	return &CreateRequest{
		Type:       Create,
		SuffixData: suffixData,
		Delta:      delta,
	}, nil
}

// NewUpdateRequest creates a new update request https://identity.foundation/sidetree/spec/#update
func NewUpdateRequest(didSuffix string, updateKey, nextUpdateKey crypto.PublicKeyJWK, signer BTCSignerVerifier, stateChange StateChange) (*UpdateRequest, error) {
	if err := stateChange.IsValid(); err != nil {
		return nil, errors.Wrap(err, "invalid state change")
	}

	// prepare reveal value
	revealValue, _, err := Commit(updateKey)
	if err != nil {
		return nil, errors.Wrap(err, "generating commitment for update key")
	}

	// prepare delta
	_, nextUpdateCommitment, err := Commit(nextUpdateKey)
	if err != nil {
		return nil, errors.Wrap(err, "generating commitment for next update key")
	}

	delta := NewDelta(nextUpdateCommitment)

	// services to add
	if len(stateChange.ServicesToAdd) > 0 {
		addServicesPatch := AddServicesAction{
			Action:   AddServices,
			Services: stateChange.ServicesToAdd,
		}
		delta.AddAddServicesAction(addServicesPatch)
	}

	// services to remove
	if len(stateChange.ServiceIDsToRemove) > 0 {
		removeServicesPatch := RemoveServicesAction{
			Action: RemoveServices,
			IDs:    stateChange.ServiceIDsToRemove,
		}
		delta.AddRemoveServicesAction(removeServicesPatch)
	}

	// public keys to add
	if len(stateChange.PublicKeysToAdd) > 0 {
		addPublicKeysPatch := AddPublicKeysAction{
			Action:     AddPublicKeys,
			PublicKeys: stateChange.PublicKeysToAdd,
		}
		delta.AddAddPublicKeysAction(addPublicKeysPatch)
	}

	// public keys to remove
	if len(stateChange.PublicKeyIDsToRemove) > 0 {
		removePublicKeysPatch := RemovePublicKeysAction{
			Action: RemovePublicKeys,
			IDs:    stateChange.PublicKeyIDsToRemove,
		}
		delta.AddRemovePublicKeysAction(removePublicKeysPatch)
	}

	deltaCanonical, err := CanonicalizeAny(delta)
	if err != nil {
		return nil, errors.Wrap(err, "canonicalizing delta")
	}
	deltaHash, err := HashEncode(deltaCanonical)
	if err != nil {
		return nil, errors.Wrap(err, "hash-encoding delta")
	}

	// prepare signed data
	toBeSigned := UpdateSignedDataObject{
		UpdateKey: updateKey,
		DeltaHash: deltaHash,
	}
	signedJWT, err := signer.SignJWT(toBeSigned)
	if err != nil {
		return nil, errors.Wrap(err, "signing update request")
	}
	return &UpdateRequest{
		Type:        Update,
		DIDSuffix:   didSuffix,
		RevealValue: revealValue,
		Delta:       delta,
		SignedData:  signedJWT,
	}, nil
}

// NewRecoverRequest creates a new recover request https://identity.foundation/sidetree/spec/#recover
func NewRecoverRequest(didSuffix string, recoveryKey, nextRecoveryKey, nextUpdateKey crypto.PublicKeyJWK, document Document, signer BTCSignerVerifier) (*RecoverRequest, error) { //revive:disable-line:argument-limit
	// prepare reveal value
	revealValue, _, err := Commit(recoveryKey)
	if err != nil {
		return nil, err
	}

	// prepare delta
	replaceAction := ReplaceAction{
		Action:   Replace,
		Document: document,
	}

	_, updateCommitment, err := Commit(nextUpdateKey)
	if err != nil {
		return nil, err
	}

	delta := NewDelta(updateCommitment)
	delta.AddReplaceAction(replaceAction)

	// prepare signed data
	deltaCanonical, err := CanonicalizeAny(delta)
	if err != nil {
		return nil, err
	}
	deltaHash, err := HashEncode(deltaCanonical)
	if err != nil {
		return nil, err
	}
	_, recoveryCommitment, err := Commit(nextRecoveryKey)
	if err != nil {
		return nil, err
	}

	toBeSigned := RecoverySignedDataObject{
		RecoveryCommitment: recoveryCommitment,
		RecoveryKey:        recoveryKey,
		DeltaHash:          deltaHash,
	}
	signedJWT, err := signer.SignJWT(toBeSigned)
	if err != nil {
		return nil, err
	}
	return &RecoverRequest{
		Type:        Recover,
		DIDSuffix:   didSuffix,
		RevealValue: revealValue,
		Delta:       delta,
		SignedData:  signedJWT,
	}, nil
}

// NewDeactivateRequest creates a new deactivate request https://identity.foundation/sidetree/spec/#deactivate
func NewDeactivateRequest(didSuffix string, recoveryKey crypto.PublicKeyJWK, signer BTCSignerVerifier) (*DeactivateRequest, error) {
	// prepare reveal value
	revealValue, _, err := Commit(recoveryKey)
	if err != nil {
		return nil, err
	}

	// prepare signed data
	toBeSigned := DeactivateSignedDataObject{
		DIDSuffix:   didSuffix,
		RecoveryKey: recoveryKey,
	}
	signedJWT, err := signer.SignJWT(toBeSigned)
	if err != nil {
		return nil, errors.Wrap(err, "signing JWT")
	}
	return &DeactivateRequest{
		Type:        Deactivate,
		DIDSuffix:   didSuffix,
		RevealValue: revealValue,
		SignedData:  signedJWT,
	}, nil
}

type StateChange struct {
	ServicesToAdd        []Service
	ServiceIDsToRemove   []string
	PublicKeysToAdd      []PublicKey
	PublicKeyIDsToRemove []string
}

func (s StateChange) IsEmpty() bool {
	return len(s.ServicesToAdd) == 0 &&
		len(s.ServiceIDsToRemove) == 0 &&
		len(s.PublicKeysToAdd) == 0 &&
		len(s.PublicKeyIDsToRemove) == 0
}

func (s StateChange) IsValid() error {
	if s.IsEmpty() {
		return errors.New("state change cannot be empty")
	}

	// check if services are valid
	// build index of services to make sure IDs are unique
	services := make(map[string]Service, len(s.ServicesToAdd))
	for _, service := range s.ServicesToAdd {
		if _, ok := services[service.ID]; ok {
			return errors.Errorf("service %s duplicated", service.ID)
		}

		if len(service.ID) > maxIDLength {
			return errors.Errorf("service<%s> id is too long", service.ID)
		}

		// make sure service is valid if it's not a dupe
		if len(service.Type) > maxServiceTypeLength {
			return errors.Errorf("service<%s> type %s is too long", service.ID, service.Type)
		}

		services[service.ID] = service
	}

	// check if public keys are valid
	// build index of public keys to add
	publicKeys := make(map[string]PublicKey, len(s.PublicKeysToAdd))
	for _, publicKey := range s.PublicKeysToAdd {
		if _, ok := publicKeys[publicKey.ID]; ok {
			return errors.Errorf("public key<%s> is duplicated", publicKey.ID)
		}

		if len(publicKey.ID) > maxIDLength {
			return errors.Errorf("public key<%s> id is too long", publicKey.ID)
		}

		publicKeys[publicKey.ID] = publicKey
	}

	// check if services to remove are valid
	for _, serviceID := range s.ServiceIDsToRemove {
		if _, ok := services[serviceID]; ok {
			return errors.Errorf("service<%s> added and removed in same request", serviceID)
		}

		if len(serviceID) > maxIDLength {
			return errors.Errorf("service<%s> id is too long", serviceID)
		}
	}

	// check if public keys to remove are valid
	for _, publicKeyID := range s.PublicKeyIDsToRemove {
		if _, ok := publicKeys[publicKeyID]; ok {
			return errors.Errorf("public key<%s> added and removed in same request", publicKeyID)
		}

		if len(publicKeyID) > maxIDLength {
			return errors.Errorf("public key<%s> id is too long", publicKeyID)
		}
	}
	return nil
}
