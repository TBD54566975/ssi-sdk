package mobile

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"

	ssi "github.com/TBD54566975/ssi-sdk/crypto"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/x25519"
)

// methods from crypto/models.go

func IsSupportedKeyType(kt string) bool {
	supported := GetSupportedKeyTypes()
	for _, t := range supported {
		if kt == t {
			return true
		}
	}
	return false
}

func GetSupportedKeyTypes() []string {
	return []string{string(ssi.Ed25519), string(ssi.X25519), string(ssi.Secp256k1), string(ssi.P224), string(ssi.P256), string(ssi.P384), string(ssi.P521), string(ssi.RSA)}
}

func IsSupportedSignatureAlg(sa string) bool {
	supported := GetSupportedSignatureAlgs()
	for _, a := range supported {
		if sa == a {
			return true
		}
	}
	return false
}

func GetSupportedSignatureAlgs() []string {
	return []string{string(ssi.EdDSA), string(ssi.ES256K), string(ssi.ES256), string(ssi.ES384), string(ssi.PS256)}
}

// methods from crypto/keys.go

func GenerateKeyByKeyType(kt string) (crypto.PublicKey, crypto.PrivateKey, error) {
	return ssi.GenerateKeyByKeyType(ssi.KeyType(kt))
}

func PubKeyToBytes(key crypto.PublicKey) ([]byte, error) {
	return ssi.PubKeyToBytes(key)
}

func BytesToPubKey(keyBytes []byte, kt string) (crypto.PublicKey, error) {
	return ssi.BytesToPubKey(keyBytes, ssi.KeyType(kt))
}

func PrivKeyToBytes(key crypto.PrivateKey) ([]byte, error) {
	return ssi.PrivKeyToBytes(key)
}
func BytesToPrivKey(keyBytes []byte, kt string) (crypto.PrivateKey, error) {
	return ssi.BytesToPrivKey(keyBytes, ssi.KeyType(kt))
}

func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ssi.GenerateEd25519Key()
}

func GenerateX25519Key() (x25519.PublicKey, x25519.PrivateKey, error) {
	return ssi.GenerateX25519Key()
}

func GenerateSecp256k1Key() (secp.PublicKey, secp.PrivateKey, error) {
	return ssi.GenerateSecp256k1Key()
}

func GenerateP224Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return ssi.GenerateP224Key()
}

func GenerateP256Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return ssi.GenerateP256Key()
}

func GenerateP384Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return ssi.GenerateP384Key()
}

func GenerateP521Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return ssi.GenerateP521Key()
}

func GenerateRSA2048Key() (rsa.PublicKey, rsa.PrivateKey, error) {
	return ssi.GenerateRSA2048Key()
}
