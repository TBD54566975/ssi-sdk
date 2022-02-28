package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/lestrrat-go/jwx/x25519"
)

type KeyType string

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

func GenerateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func GenerateX25519Key() (x25519.PublicKey, x25519.PrivateKey, error) {
	return x25519.GenerateKey(rand.Reader)
}

func GenerateSecp256k1Key() (secp.PublicKey, secp.PrivateKey, error) {
	privKey, err := secp.GeneratePrivateKey()
	if err != nil {
		return secp.PublicKey{}, secp.PrivateKey{}, err
	}
	pubKey := privKey.PubKey()
	return *pubKey, *privKey, nil
}

func GenerateP224Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P224())
}

func GenerateP256Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P256())
}

func GenerateP384Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P384())
}

func GenerateP521Key() (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	return generateECDSAKey(elliptic.P521())
}

func generateECDSAKey(curve elliptic.Curve) (ecdsa.PublicKey, ecdsa.PrivateKey, error) {
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return ecdsa.PublicKey{}, ecdsa.PrivateKey{}, err
	}
	return privKey.PublicKey, *privKey, nil
}

func GenerateRSA2048Key() (rsa.PublicKey, rsa.PrivateKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return rsa.PublicKey{}, rsa.PrivateKey{}, err
	}
	return privKey.PublicKey, *privKey, nil
}

func GetSupportedKeyTypes() []KeyType {
	return []KeyType{Ed25519, X25519, Secp256k1, P224, P256, P384, P521, RSA}
}
