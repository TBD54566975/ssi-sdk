package cryptosuite

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"filippo.io/edwards25519"
	"github.com/TBD54566975/did-sdk/util"
)

type (
	KTY string
	CRV string
)

const (
	OKP KTY = "Ed25519"
	EC  KTY = "EC"
	RSA KTY = "RSA"

	Ed25519   CRV = "Ed25519"
	X25519    CRV = "X25519"
	SECP256k1 CRV = "secp256k1"
	P256      CRV = "P-256"
	P384      CRV = "P-384"

	RSASize int = 2048
)

// PublicKeyJWK complies with RFC7517 https://datatracker.ietf.org/doc/html/rfc7517
type PublicKeyJWK struct {
	KTY    KTY    `json:"kty" validate:"required"`
	CRV    CRV    `json:"crv,omitempty"`
	X      string `json:"x,omitempty"`
	Y      string `json:"y,omitempty"`
	N      string `json:"n,omitempty"`
	E      string `json:"e,omitempty"`
	Use    string `json:"use,omitempty"`
	KeyOps string `json:"key_ops,omitempty"`
	Alg    string `json:"alg,omitempty"`
	KID    string `json:"kid,omitempty"`
}

// GenerateJSONWebKey2020 The JSONWebKey2020 type specifies a number of key type and curve pairs to enable JOSE conformance
// these pairs are supported in this library and generated via the function below
// https://w3c-ccg.github.io/lds-jws2020/#dfn-jsonwebkey2020
func GenerateJSONWebKey2020(kty KTY, crv *CRV) (crypto.PrivateKey, *PublicKeyJWK, error) {
	if kty == RSA {
		return GenerateRSAJSONWebKey2020()
	}
	if crv == nil {
		return nil, nil, errors.New("crv must be specified for non-RSA key types")
	}
	curve := *crv
	if kty == OKP {
		switch curve {
		case Ed25519:
			return GenerateEd25519JSONWebKey2020()
		case X25519:
			return GenerateX25519JSONWebKey2020()
		default:
			return nil, nil, fmt.Errorf("unsupported OKP curve: %s", curve)
		}

	}
	if kty == EC {
		switch curve {
		case SECP256k1:
			return GenerateSECP256k1JSONWebKey2020()
		case P256:
			return GenerateP256JSONWebKey2020()
		case P384:
			return GenerateP384JSONWebKey2020()
		default:
			return nil, nil, fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return nil, nil, fmt.Errorf("unsupported key type: %s", kty)
}

func Ed25519JSONWebKey2020(pubKeyBytes []byte) PublicKeyJWK {
	x := base64.URLEncoding.EncodeToString(pubKeyBytes)
	return PublicKeyJWK{
		KTY: OKP,
		CRV: Ed25519,
		X:   x,
	}
}

func GenerateEd25519JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	pubKey, privKey, err := util.GenerateEd25519Key()
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK := Ed25519JSONWebKey2020(pubKey)
	return privKey, &pubKeyJWK, nil
}

func X25519JSONWebKey2020(pubKeyBytes []byte) (*PublicKeyJWK, error) {
	point, err := edwards25519.NewGeneratorPoint().SetBytes(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	x25519PubKey := point.BytesMontgomery()
	x := base64.URLEncoding.EncodeToString(x25519PubKey)
	return &PublicKeyJWK{
		KTY: OKP,
		CRV: Ed25519,
		X:   x,
	}, nil
}

func GenerateX25519JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	// since ed25519 and x25519 have birational equivalence we do a conversion as a convenience
	// this code is officially supported by the lead Golang cryptographer
	// https://github.com/golang/go/issues/20504#issuecomment-873342677
	pubKey, privKey, err := util.GenerateEd25519Key()
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK, err := X25519JSONWebKey2020(pubKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKeyJWK, nil
}

func SECP256k1JSONWebKey2020(pubKey *secp.PublicKey) PublicKeyJWK {
	return PublicKeyJWK{
		KTY: EC,
		CRV: SECP256k1,
		X:   pubKey.X().String(),
		Y:   pubKey.Y().String(),
	}
}

func GenerateSECP256k1JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	// We use the secp256k1 implementation from Decred https://github.com/decred/dcrd
	// which is utilized in the widely accepted go bitcoin node implementation from the btcsuite project
	// https://github.com/btcsuite/btcd/blob/master/btcec/btcec.go#L23
	privKey, err := secp.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	pubKey := privKey.PubKey()
	pubKeyJWK := SECP256k1JSONWebKey2020(pubKey)
	return privKey, &pubKeyJWK, nil
}

func P256JSONWebKey2020(pubKey ecdsa.PublicKey) PublicKeyJWK {
	return PublicKeyJWK{
		KTY: EC,
		CRV: P256,
		X:   pubKey.X.String(),
		Y:   pubKey.Y.String(),
	}
}

func GenerateP256JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK := P256JSONWebKey2020(privKey.PublicKey)
	return privKey, &pubKeyJWK, nil
}

func P384JSONWebKey2020(pubKey ecdsa.PublicKey) PublicKeyJWK {
	return PublicKeyJWK{
		KTY: EC,
		CRV: P384,
		X:   pubKey.X.String(),
		Y:   pubKey.Y.String(),
	}
}

func GenerateP384JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK := P384JSONWebKey2020(privKey.PublicKey)
	return privKey, &pubKeyJWK, nil
}

func RSAJSONWebKey2020(pubKey rsa.PublicKey) PublicKeyJWK {
	return PublicKeyJWK{
		KTY: RSA,
		N:   pubKey.N.String(),
		E:   strconv.Itoa(pubKey.E),
	}
}

func GenerateRSAJSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSASize)
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK := RSAJSONWebKey2020(privateKey.PublicKey)
	return privateKey, &pubKeyJWK, nil
}
