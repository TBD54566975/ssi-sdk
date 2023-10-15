package crypto

type (
	Proof              any
	KeyType            string
	HashType           string
	SignatureAlgorithm string
)

const (
	Ed25519        KeyType = "Ed25519"
	X25519         KeyType = "X25519"
	SECP256k1      KeyType = "secp256k1"
	SECP256k1ECDSA KeyType = "secp256k1-ECDSA"
	P224           KeyType = "P-224"
	P256           KeyType = "P-256"
	P384           KeyType = "P-384"
	P521           KeyType = "P-521"
	RSA            KeyType = "RSA"
	BLS12381G1     KeyType = "BLS12381G1"
	BLS12381G2     KeyType = "BLS12381G2"
	Dilithium2     KeyType = "Dilithium2"
	Dilithium3     KeyType = "Dilithium3"
	Dilithium5     KeyType = "Dilithium5"

	RSAKeySize int = 2048
)

const (
	SHA256 HashType = "SHA256"
)

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

	// Experimental

	Dilithium2Sig SignatureAlgorithm = "Dilithium2"
	Dilithium3Sig SignatureAlgorithm = "Dilithium3"
	Dilithium5Sig SignatureAlgorithm = "Dilithium5"
)

func (kt KeyType) String() string {
	return string(kt)
}

// IsSupportedKeyType returns true if the key type is supported
func IsSupportedKeyType(kt KeyType) bool {
	supported := GetSupportedKeyTypes()
	for _, t := range supported {
		if kt == t {
			return true
		}
	}
	return false
}

// GetSupportedJWKKeyTypes returns a list of supported JWK key types
// RSA, secp256k1, and P-224 are not supported by the lib we use for JWK
func GetSupportedJWKKeyTypes() []KeyType {
	return []KeyType{Ed25519, X25519, SECP256k1, SECP256k1ECDSA, P256, P384, P521}
}

// GetSupportedKeyTypes returns a list of supported key types
func GetSupportedKeyTypes() []KeyType {
	return []KeyType{Ed25519, X25519, SECP256k1, SECP256k1ECDSA, P224, P256, P384, P521, RSA}
}

// GetExperimentalKeyTypes returns a list of experimental key types
func GetExperimentalKeyTypes() []KeyType {
	return []KeyType{Dilithium2, Dilithium3, Dilithium5}
}

// IsSupportedSignatureAlg returns true if the signature algorithm is supported
func IsSupportedSignatureAlg(sa SignatureAlgorithm) bool {
	supported := GetSupportedSignatureAlgs()
	for _, a := range supported {
		if sa == a {
			return true
		}
	}
	return false
}

// GetSupportedSignatureAlgs returns a list of supported signature algorithms
func GetSupportedSignatureAlgs() []SignatureAlgorithm {
	return []SignatureAlgorithm{EdDSA, ES256K, ES256, ES384, PS256}
}

// GetExperimentalSignatureAlgs returns a list of experimental signature algorithms
func GetExperimentalSignatureAlgs() []SignatureAlgorithm {
	return []SignatureAlgorithm{Dilithium2Sig, Dilithium3Sig, Dilithium5Sig}
}
