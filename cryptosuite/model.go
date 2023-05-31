package cryptosuite

type (
	SignatureType string
	ProofPurpose  string
	PayloadFormat string
	LDKeyType     string
)

func (ld LDKeyType) String() string {
	return string(ld)
}

const (
	W3CSecurityContext                  string = "https://w3id.org/security/v2"
	Ed25519VerificationKey2020Context   string = "https://w3id.org/security/suites/ed25519-2020/v1"
	X25519KeyAgreementKey2020Context    string = "https://w3id.org/security/suites/x25519-2020/v1"
	SECP256k1VerificationKey2019Context string = "https://w3id.org/security/suites/secp256k1-2019/v1"
	JSONWebKey2020Context               string = "https://w3id.org/security/suites/jws-2020/v1"
	Multikey2021Context                 string = "https://w3id.org/security/suites/multikey-2021/v1"
	BLS12381G2Key2020Context            string = "https://w3id.org/security/suites/bls12381-2020/v1"

	AssertionMethod ProofPurpose = "assertionMethod"
	Authentication  ProofPurpose = "authentication"

	JWTFormat PayloadFormat = "jwt"
	LDPFormat PayloadFormat = "ldp"
)

const (
	JSONWebKey2020Type                LDKeyType = "JsonWebKey2020"
	X25519KeyAgreementKey2020         LDKeyType = "X25519KeyAgreementKey2020"
	Ed25519VerificationKey2020        LDKeyType = "Ed25519VerificationKey2020"
	X25519KeyAgreementKey2019         LDKeyType = "X25519KeyAgreementKey2019"
	Ed25519VerificationKey2018        LDKeyType = "Ed25519VerificationKey2018"
	ECDSASECP256k1VerificationKey2019 LDKeyType = "EcdsaSecp256k1VerificationKey2019"
	MultikeyType                      LDKeyType = "Multikey"
	P256Key2021                       LDKeyType = "P256Key2021"
	P384Key2021                       LDKeyType = "P384Key2021"
	P521Key2021                       LDKeyType = "P521Key2021"
	BLS12381G1Key2020                 LDKeyType = "Bls12381G1Key2020"
	BLS12381G2Key2020                 LDKeyType = "Bls12381G2Key2020"
)
