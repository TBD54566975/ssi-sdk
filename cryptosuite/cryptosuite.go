package cryptosuite

type (
	KeyType string
	Proof   interface{}
)

const (
	JsonWebKey2020 KeyType = "JsonWebKey2020"
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

type CryptoSuiteSign interface {
}

type CryptoSuiteVerify interface {
}

type Provable interface {
	GetProof() *Proof
	SetProof(p *Proof)
}
