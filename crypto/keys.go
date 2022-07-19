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

// PubKeyToBytes constructs a byte representation of a public key, for a set number of supported key types
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

// BytesToPubKey reconstructs a public key given some bytes and a target key type
// It is assumed the key was turned into byte form using the sibling method `PubKeyToBytes`
func BytesToPubKey(keyBytes []byte, kt KeyType) (crypto.PublicKey, error) {
	switch kt {
	case Ed25519, X25519:
		return keyBytes, nil
	case Secp256k1:
		pubKey, err := secp.ParsePubKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *pubKey, nil
	case P224:
		x, y := elliptic.Unmarshal(elliptic.P224(), keyBytes)
		return ecdsa.PublicKey{
			Curve: elliptic.P224(),
			X:     x,
			Y:     y,
		}, nil
	case P256:
		x, y := elliptic.Unmarshal(elliptic.P256(), keyBytes)
		return ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}, nil
	case P384:
		x, y := elliptic.Unmarshal(elliptic.P384(), keyBytes)
		return ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     x,
			Y:     y,
		}, nil
	case P521:
		x, y := elliptic.Unmarshal(elliptic.P521(), keyBytes)
		return ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     x,
			Y:     y,
		}, nil
	case RSA:
		pubKey, err := x509.ParsePKCS1PublicKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *pubKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}
}

// PrivKeyToBytes constructs a byte representation of a private key, for a set number of supported key types
func PrivKeyToBytes(key crypto.PrivateKey) ([]byte, error) {
	ed25519Key, ok := key.(ed25519.PrivateKey)
	if ok {
		return ed25519Key, nil
	}

	x25519Key, ok := key.(x25519.PrivateKey)
	if ok {
		return x25519Key, nil
	}

	secp256k1Key, ok := key.(secp.PrivateKey)
	if ok {
		return secp256k1Key.Serialize(), nil
	}

	ecdsaKey, ok := key.(ecdsa.PrivateKey)
	if ok {
		return x509.MarshalECPrivateKey(&ecdsaKey)
	}

	rsaKey, ok := key.(rsa.PrivateKey)
	if ok {
		return x509.MarshalPKCS1PrivateKey(&rsaKey), nil
	}

	return nil, errors.New("unknown private key type; could not convert to bytes")
}

// BytesToPrivKey reconstructs a private key given some bytes and a target key type
// It is assumed the key was turned into byte form using the sibling method `PrivKeyToBytes`
func BytesToPrivKey(keyBytes []byte, kt KeyType) (crypto.PrivateKey, error) {
	switch kt {
	case Ed25519, X25519:
		return keyBytes, nil
	case Secp256k1:
		return *secp.PrivKeyFromBytes(keyBytes), nil
	case P224, P256, P384, P521:
		privKey, err := x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *privKey, nil
	case RSA:
		privKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
		return *privKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kt)
	}
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
