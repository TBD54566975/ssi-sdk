package cryptosuite

import (
	"crypto"
	"encoding/json"

	"github.com/TBD54566975/did-sdk/util"

	"github.com/gobuffalo/packr/v2"
)

type (
	KeyType       string
	SignatureType string
	ProofPurpose  string
	Proof         interface{}
)

const (
	W3CSecurityContext                    = "https://w3id.org/security/v1"
	JWS2020LinkedDataContext string       = "https://w3id.org/security/suites/jws-2020/v1"
	AssertionMethod          ProofPurpose = "assertionMethod"
)

var (
	contextBox = packr.New("Known JSON-LD Contexts", "./context")
)

// CryptoSuite encapsulates the behavior of a proof type as per the W3C specification
// on data integrity https://w3c-ccg.github.io/data-integrity-spec/#creating-new-proof-types
type CryptoSuite interface {
	CryptoSuiteInfo

	// Sign https://w3c-ccg.github.io/data-integrity-spec/#proof-algorithm
	Sign(s Signer, p Provable) (*Provable, error)
	// Verify https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
	Verify(v Verifier, p Provable) error
}

type CryptoSuiteInfo interface {
	ID() string
	Type() KeyType
	CanonicalizationAlgorithm() string
	MessageDigestAlgorithm() crypto.Hash
	SignatureAlgorithm() SignatureType
	RequiredContexts() []string
}

// CryptoSuiteProofType is an interface that defines functionality needed to sign and verify data
// It encapsulates the functionality defined by the data integrity proof type specification
// https://w3c-ccg.github.io/data-integrity-spec/#creating-new-proof-types
type CryptoSuiteProofType interface {
	Marshal(data interface{}) ([]byte, error)
	Canonicalize(marshaled []byte) (*string, error)
	// CreateVerifyHash https://w3c-ccg.github.io/data-integrity-spec/#create-verify-hash-algorithm
	CreateVerifyHash(provable Provable, proof Proof, proofOptions *ProofOptions) ([]byte, error)
	Digest(tbd []byte) ([]byte, error)
}

type Provable interface {
	GetProof() *Proof
	SetProof(p *Proof)
}

type Signer interface {
	KeyID() string
	KeyType() KeyType
	SignatureType() SignatureType
	SigningAlgorithm() string
	Sign(tbs []byte) ([]byte, error)
}

type Verifier interface {
	KeyID() string
	KeyType() KeyType
	Verify(message, signature []byte) error
}

type ProofOptions struct {
	// JSON-LD contexts to add to the proof
	Contexts []string
}

func GetContextsFromProvable(p Provable) ([]string, error) {
	provableBytes, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var genericProvable map[string]interface{}
	if err := json.Unmarshal(provableBytes, &genericProvable); err != nil {
		return nil, err
	}
	contexts, ok := genericProvable["@context"]
	if !ok {
		return nil, nil
	}
	strContexts, err := util.InterfaceToStrings(contexts)
	if err != nil {
		return nil, err
	}
	return strContexts, nil
}

func getKnownContext(fileName string) (string, error) {
	return contextBox.FindString(fileName)
}
