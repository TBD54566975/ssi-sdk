package cryptosuite

type (
	SignatureType string
	ProofPurpose  string
	PayloadFormat string
)

const (
	W3CSecurityContext       string = "https://w3id.org/security/v1"
	JWS2020LinkedDataContext string = "https://w3id.org/security/suites/jws-2020/v1"

	AssertionMethod ProofPurpose = "assertionMethod"
	Authentication  ProofPurpose = "authentication"

	JWTFormat PayloadFormat = "jwt"
	LDPFormat PayloadFormat = "ldp"
)

const (
	// DID Key Types

	X25519KeyAgreementKey2020         LDKeyType = "X25519KeyAgreementKey2020"
	Ed25519VerificationKey2020        LDKeyType = "Ed25519VerificationKey2020"
	X25519KeyAgreementKey2019         LDKeyType = "X25519KeyAgreementKey2019"
	Ed25519VerificationKey2018        LDKeyType = "Ed25519VerificationKey2018"
	EcdsaSecp256k1VerificationKey2019 LDKeyType = "EcdsaSecp256k1VerificationKey2019"
)