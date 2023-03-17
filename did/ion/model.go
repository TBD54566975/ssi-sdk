package ion

import (
	"github.com/TBD54566975/ssi-sdk/crypto"
)

type Document struct {
	PublicKeys []PublicKey
	Services   []Service
}

type Service struct {
	ID              string
	Type            string
	ServiceEndpoint any
}

type AddServicesAction struct {
	Action   string
	Services []Service
}

type RemoveServicesAction struct {
	Action string
	IDs    []string
}

type PublicKey struct {
	ID           string
	Type         string
	PublicKeyJWK crypto.PublicKeyJWK
	Purposes     []PublicKeyPurpose
}

type AddPublicKeysAction struct {
	Action     string
	PublicKeys []PublicKey
}

type RemovePublicKeysAction struct {
	Action string
	IDs    []string
}

type CreateRequest struct {
	Type       OperationType
	SuffixData struct {
		DeltaHash          string
		RecoveryCommitment string
	}
	Delta []struct {
		UpdateCommitment string
		Patches          struct {
			Action   string
			Document Document
		}
	}
}

// Patches Only one of these values should be set
type Patches struct {
	*AddServicesAction
	*AddPublicKeysAction
	*RemoveServicesAction
	*RemovePublicKeysAction
}

type UpdateRequest struct {
	Type        OperationType
	DIDSuffix   string
	RevealValue string
	Delta       []struct {
		UpdateCommitment string
		Patches          []Patches
	}
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
	Delta       []struct {
		UpdateCommitment string
		Patches          struct {
			Action   string
			Document Document
		}
	}
	SignedData string
}
