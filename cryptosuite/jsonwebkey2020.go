package cryptosuite

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strconv"
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
//https://w3c-ccg.github.io/lds-jws2020/#dfn-jsonwebkey2020
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
		case X25519:
		default:
			return nil, nil, fmt.Errorf("unsupported OKP curve: %s", curve)
		}

	}
	if kty == EC {
		switch curve {
		case SECP256k1:
		case P256:
		case P384:
		default:
			return nil, nil, fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return nil, nil, fmt.Errorf("unsupported key type: %s", kty)
}

func GenerateEd25519JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	return nil, nil, nil
}

func GenerateX25519JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	return nil, nil, nil
}

func GenerateSECP256k1JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	return nil, nil, nil
}

func GenerateP256JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	return nil, nil, nil
}

func GenerateP384JSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	return nil, nil, nil
}

func GenerateRSAJSONWebKey2020() (crypto.PrivateKey, *PublicKeyJWK, error) {
	rsaPrivKey, err := generateRSAKey()
	if err != nil {
		return nil, nil, err
	}
	return rsaPrivKey, &PublicKeyJWK{
		KTY: RSA,
		N:   rsaPrivKey.N.String(),
		E:   strconv.Itoa(rsaPrivKey.E),
	}, nil
}

func generateRSAKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSASize)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}
