package cryptosuite

import "github.com/gobuffalo/packr/v2"

type (
	KeyType string
	Proof   interface{}
)

const (
	JsonWebKey2020           KeyType = "JsonWebKey2020"
	JWS2020LinkedDataContext string  = "https://w3id.org/security/suites/jws-2020/v1"
)

var (
	contextBox = packr.New("Known JSON-LD Contexts", "./context")
)

// CryptoSuite encapsulates the behavior of a proof type as per the W3C specification
// on data integrity https://w3c-ccg.github.io/data-integrity-spec/#creating-new-proof-types
type CryptoSuite interface {
	ID() string
	Type() string
	CanonicalizationAlgorithm() string
	DigestAlgorithm() string
	ProofAlgorithm() string
}

type CryptoSuiteProofs interface {
	// CreateProof https://w3c-ccg.github.io/data-integrity-spec/#proof-algorithm
	CreateProof()
	// VerifyProof https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
	VerifyProof()
	// CreateVerifyHash https://w3c-ccg.github.io/data-integrity-spec/#create-verify-hash-algorithm
	CreateVerifyHash()
}

type Provable interface {
	GetProof() *Proof
	SetProof(p *Proof)
}

type Signer interface {
	KeyID() string
	KeyType() KeyType
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
