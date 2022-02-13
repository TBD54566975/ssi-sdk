package cryptosuite

// https://w3c-ccg.github.io/ld-cryptosuite-registry/#jsonwebsignature2020

const (
	JWSSignatureSuiteID                        string = "https://w3c-ccg.github.io/security-vocab/#JsonWebSignature2020"
	JWSSignatureSuiteType                      string = "JsonWebKey2020"
	JWSSignatureSuiteCanonicalizationAlgorithm string = "https://w3id.org/security#URDNA2015"
	// JWSSignatureSuiteDigestAlgorithm uses https://www.rfc-editor.org/rfc/rfc4634
	JWSSignatureSuiteDigestAlgorithm string = "SHA-256"
	// JWSSignatureSuiteProofAlgorithm  uses https://www.rfc-editor.org/rfc/rfc7797
	JWSSignatureSuiteProofAlgorithm string = "JSON Web Signature (JWS) Unencoded Payload Option"
)

type JWSSignatureSuite struct{}

func (j JWSSignatureSuite) ID() string {
	return JWSSignatureSuiteID
}

func (j JWSSignatureSuite) Type() string {
	return JWSSignatureSuiteType
}

func (j JWSSignatureSuite) CanonicalizationAlgorithm() string {
	return JWSSignatureSuiteCanonicalizationAlgorithm
}

func (j JWSSignatureSuite) DigestAlgorithm() string {
	return JWSSignatureSuiteDigestAlgorithm
}

func (j JWSSignatureSuite) ProofAlgorithm() string {
	return JWSSignatureSuiteProofAlgorithm
}
