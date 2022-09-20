package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/x25519"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// PrivateKeyJWK complies with RFC7517 https://datatracker.ietf.org/doc/html/rfc7517
type PrivateKeyJWK struct {
	KTY    string `json:"kty" validate:"required"`
	CRV    string `json:"crv,omitempty"`
	X      string `json:"x,omitempty"`
	Y      string `json:"y,omitempty"`
	N      string `json:"n,omitempty"`
	E      string `json:"e,omitempty"`
	Use    string `json:"use,omitempty"`
	KeyOps string `json:"key_ops,omitempty"`
	Alg    string `json:"alg,omitempty"`
	KID    string `json:"kid,omitempty"`
	D      string `json:"d,omitempty"`
	DP     string `json:"dp,omitempty"`
	DQ     string `json:"dq,omitempty"`
	P      string `json:"p,omitempty"`
	Q      string `json:"q,omitempty"`
	QI     string `json:"qi,omitempty"`
}

// PublicKeyJWK complies with RFC7517 https://datatracker.ietf.org/doc/html/rfc7517
type PublicKeyJWK struct {
	KTY    string `json:"kty" validate:"required"`
	CRV    string `json:"crv,omitempty"`
	X      string `json:"x,omitempty"`
	Y      string `json:"y,omitempty"`
	N      string `json:"n,omitempty"`
	E      string `json:"e,omitempty"`
	Use    string `json:"use,omitempty"`
	KeyOps string `json:"key_ops,omitempty"`
	Alg    string `json:"alg,omitempty"`
	KID    string `json:"kid,omitempty"`
}

func ToPrivateKeyJWK(key crypto.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	switch key.(type) {
	case ed25519.PrivateKey:
		return JWKFromEd25519PrivateKey(key.(ed25519.PrivateKey))
	case x25519.PrivateKey:
		return JWKFromX25519PrivateKey(key.(x25519.PrivateKey))
	case secp.PrivateKey:
		return JWKFromSECP256k1PrivateKey(key.(secp256k1.PrivateKey))
	case ecdsa.PrivateKey:
		return JWKFromECDSAPrivateKey(key.(ecdsa.PrivateKey))
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

func ToPublicKeyJWK(key jwk.Key) (*PublicKeyJWK, error) {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	var pubKeyJWK PublicKeyJWK
	if err := json.Unmarshal(keyBytes, &pubKeyJWK); err != nil {
		return nil, err
	}
	return &pubKeyJWK, nil
}

func JWKFromEd25519PrivateKey(key ed25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ed25519JWK := jwk.NewOKPPrivateKey()
	if err := ed25519JWK.FromRaw(key); err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate ed25519 jwk")
	}
	kty := ed25519JWK.KeyType().String()
	crv := ed25519JWK.Crv().String()
	x := encodeToBase64RawURL(ed25519JWK.X())

	publicKeyJWK := PublicKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
	}
	privateKeyJWK := PrivateKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
		D:   encodeToBase64RawURL(ed25519JWK.D()),
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

func JWKFromX25519PrivateKey(key x25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	x25519JWK := jwk.NewOKPPrivateKey()
	if err := x25519JWK.FromRaw(key); err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate x25519 jwk")
	}
	kty := x25519JWK.KeyType().String()
	crv := x25519JWK.Crv().String()
	x := encodeToBase64RawURL(x25519JWK.X())

	publicKey := PublicKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
	}
	privateKey := PrivateKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
		D:   encodeToBase64RawURL(x25519JWK.D()),
	}
	return &publicKey, &privateKey, nil
}

func JWKFromSECP256k1PrivateKey(key secp.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaPrivKey := key.ToECDSA()
	secp256k1JWK := jwk.NewECDSAPrivateKey()
	if err := secp256k1JWK.FromRaw(ecdsaPrivKey); err != nil {
		err := errors.Wrap(err, "failed to generate secp256k1 jwk")
		logrus.WithError(err).Error("could not extract key from raw private key")
		return nil, nil, err
	}
	kty := secp256k1JWK.KeyType().String()
	crv := secp256k1JWK.Crv().String()
	x := encodeToBase64RawURL(secp256k1JWK.X())
	y := encodeToBase64RawURL(secp256k1JWK.Y())

	publicKeyJWK := PublicKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
		Y:   y,
	}
	privateKeyJWK := PrivateKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
		Y:   y,
		D:   encodeToBase64RawURL(secp256k1JWK.D()),
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

func JWKFromECDSAPrivateKey(key ecdsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaKey := jwk.NewECDSAPrivateKey()
	if err := ecdsaKey.FromRaw(&key); err != nil {
		err := errors.Wrap(err, "failed to generate ecdsa jwk")
		logrus.WithError(err).Error("could not extract key from raw private key")
		return nil, nil, err
	}
	kty := ecdsaKey.KeyType().String()
	crv := ecdsaKey.Crv().String()
	x := encodeToBase64RawURL(ecdsaKey.X())
	y := encodeToBase64RawURL(ecdsaKey.Y())

	publicKeyJWK := PublicKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
		Y:   y,
	}
	privateKeyJWK := PrivateKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
		Y:   y,
		D:   encodeToBase64RawURL(ecdsaKey.D()),
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

func encodeToBase64RawURL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
