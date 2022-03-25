package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	"github.com/pkg/errors"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/lestrrat-go/jwx/x25519"
)

// GenerateKeyByKeyType creates a brand-new key, returning the public and private key for the given key type
func GenerateKeyByKeyType(kt KeyType) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch kt {
	case Ed25519:
		return GenerateEd25519Key()
	case X25519:
		return GenerateX25519Key()
	case Secp256k1:
		return GenerateSecp256k1Key()
	case P224:
		return GenerateP224Key()
	case P256:
		return GenerateP256Key()
	case P384:
		return GenerateP384Key()
	case P521:
		return GenerateP521Key()
	case RSA:
		return GenerateRSA2048Key()
	}
	return nil, nil, fmt.Errorf("unsupported key type: %s", kt)
}

func PubKeyToBytes(key crypto.PublicKey) ([]byte, error) {
	ed25519Key, ok := key.(ed25519.PublicKey)
	if ok {
		return ed25519Key, nil
	}

	x25519Key, ok := key.(x25519.PublicKey)
	if ok {
		return x25519Key, nil
	}

	secp256k1Key, ok := key.(secp.PublicKey)
	if ok {
		return secp256k1Key.SerializeCompressed(), nil
	}

	ecdsaKey, ok := key.(ecdsa.PublicKey)
	if ok {
		return elliptic.Marshal(ecdsaKey.Curve, ecdsaKey.X, ecdsaKey.Y), nil
	}

	rsaKey, ok := key.(rsa.PublicKey)
	if ok {
		return x509.MarshalPKCS1PublicKey(&rsaKey), nil
	}

	return nil, errors.New("unknown public key type; could not convert to bytes")
}

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
