package cryptosuite

import (
	"crypto"

	"github.com/gobuffalo/packr/v2"
)

type (
	KeyType       string
	SignatureType string
	ProofPurpose  string
	Proof         interface{}
)

const (
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
	CryptoSuiteProofs
}

type CryptoSuiteInfo interface {
	ID() string
	Type() KeyType
	CanonicalizationAlgorithm() string
	MessageDigestAlgorithm() crypto.Hash
	SignatureAlgorithm() string
	RequiredContexts() []string
}

type CryptoSuiteProofs interface {
	// Create and Verify are they key two methods exposed by this interface

	// CreateProof https://w3c-ccg.github.io/data-integrity-spec/#proof-algorithm
	CreateProof(s Signer, p Provable) (*Provable, error)
	// VerifyProof https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
	VerifyProof(v Verifier, p Provable) error

	// The methods below are dependencies of Create and Verify Proof

	Marshal(p Provable) ([]byte, error)
	Canonicalize(marshaled []byte) (*string, error)
	// CreateVerifyHash https://w3c-ccg.github.io/data-integrity-spec/#create-verify-hash-algorithm
	CreateVerifyHash(canonicalized []byte) ([]byte, error)
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

func getKnownContext(fileName string) (string, error) {
	return contextBox.FindString(fileName)
}
