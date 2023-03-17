package ion

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
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
	recoveryKeyCanonical, err := CanonicalizeAny(recoveryKey)
	if err != nil {
		return nil, err
	}
	revealValue, err := HashEncode(recoveryKeyCanonical)
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
