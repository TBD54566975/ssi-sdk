package ion

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
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
