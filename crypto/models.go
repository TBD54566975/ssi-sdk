package crypto

type (
	Proof              interface{}
	KeyType            string
	SignatureAlgorithm string
)

const (
	Ed25519   KeyType = "Ed25519"
	X25519    KeyType = "X25519"
	Secp256k1 KeyType = "secp256k1"
	P224      KeyType = "P-224"
	P256      KeyType = "P-256"
	P384      KeyType = "P-384"
	P521      KeyType = "P-521"
	RSA       KeyType = "RSA"

	RSAKeySize int = 2048
)

func (kt KeyType) String() string {
	return string(kt)
}

const (
	// EdDSA uses an ed25519 key
	EdDSA SignatureAlgorithm = "EdDSA"
	// ES256K uses a secp256k1 key
	ES256K SignatureAlgorithm = "ES256K"
	// ES256 uses a p-256 curve key
	ES256 SignatureAlgorithm = "ES256"
	// ES384 uses a p-384 curve key
	ES384 SignatureAlgorithm = "ES384"
	// PS256 uses a 2048-bit RSA key
	PS256 SignatureAlgorithm = "PS256"
)

func (s SignatureAlgorithm) String() string {
	return string(s)
}

func IsSupportedKeyType(kt KeyType) bool {
	supported := GetSupportedKeyTypes()
	for _, t := range supported {
		if kt == t {
			return true
		}
	}
	return false
}

func GetSupportedKeyTypes() []KeyType {
	return []KeyType{Ed25519, X25519, Secp256k1, P224, P256, P384, P521, RSA}
}

func IsSupportedSignatureAlg(sa SignatureAlgorithm) bool {
	supported := GetSupportedSignatureAlgs()
	for _, a := range supported {
		if sa == a {
			return true
		}
	}
	return false
}

func GetSupportedSignatureAlgs() []SignatureAlgorithm {
	return []SignatureAlgorithm{EdDSA, ES256K, ES256, ES384, PS256}
}
