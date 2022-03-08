package cryptosuite

import (
	"crypto"

	. "github.com/TBD54566975/did-sdk/util"
	"github.com/goccy/go-json"

	"github.com/gobuffalo/packr/v2"
)

type (
	Proof         interface{}
	SignatureType string
	ProofPurpose  string
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
	// this method mutates the provided provable object, adding a `proof` block`
	Sign(s Signer, p Provable) error
	// Verify https://w3c-ccg.github.io/data-integrity-spec/#proof-verification-algorithm
	Verify(v Verifier, p Provable) error
}

type CryptoSuiteInfo interface {
	ID() string
	Type() LDKeyType
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
	KeyType() string
	SignatureType() SignatureType
	SigningAlgorithm() string
	Sign(tbs []byte) ([]byte, error)
}

type Verifier interface {
	KeyID() string
	KeyType() string
	Verify(message, signature []byte) error
}

type ProofOptions struct {
	// JSON-LD contexts to add to the proof
	Contexts []interface{}
}

// GetContextsFromProvable searches from a Linked Data `@context` property in the document and returns the value
// associated with the context, if it exists.
func GetContextsFromProvable(p Provable) ([]interface{}, error) {
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
	interfaceContexts, err := InterfaceToInterfaceArray(contexts)
	if err != nil {
		return nil, err
	}
	return interfaceContexts, nil
}

// attempt to verify that string context(s) exist in the context interface
func ensureRequiredContexts(context []interface{}, requiredContexts []string) []interface{} {
	required := make(map[string]bool)
	for _, v := range requiredContexts {
		required[v] = true
	}

	for _, v := range context {
		vStr, ok := v.(string)
		// if it's a string, check to see if it's required
		if ok {
			req, ok := required[vStr]
			// if it's required and has a true value, we can check it off
			if ok && req {
				required[vStr] = false
			}
		}
	}

	// for all remaining true values, add it to the result
	for k, v := range required {
		if v {
			context = append(context, k)
		}
	}
	return context
}

func getKnownContext(fileName string) (string, error) {
	return contextBox.FindString(fileName)
}
