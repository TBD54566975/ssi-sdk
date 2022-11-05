package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

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

// JWKToPrivateKeyJWK converts a JWK to a PrivateKeyJWK
func JWKToPrivateKeyJWK(key jwk.Key) (*PrivateKeyJWK, error) {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(keyBytes, &privateKeyJWK); err != nil {
		return nil, err
	}
	return &privateKeyJWK, nil
}

// JWKToPublicKeyJWK converts a JWK to a PublicKeyJWK
func JWKToPublicKeyJWK(key jwk.Key) (*PublicKeyJWK, error) {
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

// PublicKeyToPublicKeyJWK converts a public key to a PublicKeyJWK
func PublicKeyToPublicKeyJWK(key crypto.PublicKey) (*PublicKeyJWK, error) {
	switch key.(type) {
	case rsa.PublicKey:
		return jwkFromRSAPublicKey(key.(rsa.PublicKey))
	case ed25519.PublicKey:
		return jwkFromEd25519PublicKey(key.(ed25519.PublicKey))
	case x25519.PublicKey:
		return jwkFromX25519PublicKey(key.(x25519.PublicKey))
	case secp256k1.PublicKey:
		return jwkFromSECP256k1PublicKey(key.(secp256k1.PublicKey))
	case ecdsa.PublicKey:
		return jwkFromECDSAPublicKey(key.(ecdsa.PublicKey))
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}
}

// PrivateKeyToPrivateKeyJWK converts a private key to a PrivateKeyJWK
func PrivateKeyToPrivateKeyJWK(key crypto.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	switch key.(type) {
	case rsa.PrivateKey:
		return jwkFromRSAPrivateKey(key.(rsa.PrivateKey))
	case ed25519.PrivateKey:
		return jwkFromEd25519PrivateKey(key.(ed25519.PrivateKey))
	case x25519.PrivateKey:
		return jwkFromX25519PrivateKey(key.(x25519.PrivateKey))
	case secp256k1.PrivateKey:
		return jwkFromSECP256k1PrivateKey(key.(secp256k1.PrivateKey))
	case ecdsa.PrivateKey:
		return jwkFromECDSAPrivateKey(key.(ecdsa.PrivateKey))
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

// jwkFromRSAPrivateKey converts a RSA private key to a JWK
func jwkFromRSAPrivateKey(key rsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	rsaJWK := jwk.NewRSAPrivateKey()
	if err := rsaJWK.FromRaw(&key); err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate rsa jwk")
	}
	kty := rsaJWK.KeyType().String()
	n := encodeToBase64RawURL(rsaJWK.N())
	e := encodeToBase64RawURL(rsaJWK.E())

	publicKeyJWK := PublicKeyJWK{
		KTY: kty,
		N:   n,
		E:   e,
	}
	privateKeyJWK := PrivateKeyJWK{
		KTY: kty,
		N:   n,
		E:   e,
		D:   encodeToBase64RawURL(rsaJWK.D()),
		DP:  encodeToBase64RawURL(rsaJWK.DP()),
		DQ:  encodeToBase64RawURL(rsaJWK.DQ()),
		P:   encodeToBase64RawURL(rsaJWK.P()),
		Q:   encodeToBase64RawURL(rsaJWK.Q()),
		QI:  encodeToBase64RawURL(rsaJWK.QI()),
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkFromRSAPublicKey converts a RSA public key to a JWK
func jwkFromRSAPublicKey(key rsa.PublicKey) (*PublicKeyJWK, error) {
	rsaJWK := jwk.NewRSAPublicKey()
	if err := rsaJWK.FromRaw(&key); err != nil {
		return nil, errors.Wrap(err, "failed to generate rsa jwk")
	}
	kty := rsaJWK.KeyType().String()
	n := encodeToBase64RawURL(rsaJWK.N())
	e := encodeToBase64RawURL(rsaJWK.E())
	return &PublicKeyJWK{
		KTY: kty,
		N:   n,
		E:   e,
	}, nil
}

// jwkFromEd25519PrivateKey converts a Ed25519 private key to a JWK
func jwkFromEd25519PrivateKey(key ed25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
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

// jwkFromEd25519PublicKey converts a Ed25519 public key to a JWK
func jwkFromEd25519PublicKey(key ed25519.PublicKey) (*PublicKeyJWK, error) {
	ed25519JWK := jwk.NewOKPPublicKey()
	if err := ed25519JWK.FromRaw(key); err != nil {
		return nil, errors.Wrap(err, "failed to generate ed25519 jwk")
	}
	kty := ed25519JWK.KeyType().String()
	crv := ed25519JWK.Crv().String()
	x := encodeToBase64RawURL(ed25519JWK.X())
	return &PublicKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
	}, nil
}

// jwkFromX25519PrivateKey converts a X25519 private key to a JWK
func jwkFromX25519PrivateKey(key x25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	return jwkFromEd25519PrivateKey(ed25519.PrivateKey(key))
}

// jwkFromX25519PublicKey converts a X25519 public key to a JWK
func jwkFromX25519PublicKey(key x25519.PublicKey) (*PublicKeyJWK, error) {
	return jwkFromEd25519PublicKey(ed25519.PublicKey(key))
}

// jwkFromSECP256k1PrivateKey converts a SECP256k1 private key to a JWK
func jwkFromSECP256k1PrivateKey(key secp256k1.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
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

// jwkFromSECP256k1PublicKey converts a SECP256k1 public key to a JWK
func jwkFromSECP256k1PublicKey(key secp256k1.PublicKey) (*PublicKeyJWK, error) {
	ecdsaPubKey := key.ToECDSA()
	secp256k1JWK := jwk.NewECDSAPublicKey()
	if err := secp256k1JWK.FromRaw(ecdsaPubKey); err != nil {
		err := errors.Wrap(err, "failed to generate secp256k1 jwk")
		logrus.WithError(err).Error("could not extract key from raw public key")
		return nil, err
	}
	kty := secp256k1JWK.KeyType().String()
	crv := secp256k1JWK.Crv().String()
	x := encodeToBase64RawURL(secp256k1JWK.X())
	y := encodeToBase64RawURL(secp256k1JWK.Y())
	return &PublicKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
		Y:   y,
	}, nil
}

// jwkFromECDSAPrivateKey converts a ECDSA private key to a JWK
func jwkFromECDSAPrivateKey(key ecdsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaKey := jwk.NewECDSAPrivateKey()
	if err := ecdsaKey.FromRaw(&key); err != nil {
		err = errors.Wrap(err, "failed to generate ecdsa jwk")
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

// jwkFromECDSAPublicKey converts a ECDSA public key to a JWK
func jwkFromECDSAPublicKey(key ecdsa.PublicKey) (*PublicKeyJWK, error) {
	ecdsaKey := jwk.NewECDSAPublicKey()
	if err := ecdsaKey.FromRaw(&key); err != nil {
		err = errors.Wrap(err, "failed to generate ecdsa jwk")
		logrus.WithError(err).Error("could not extract key from raw private key")
		return nil, err
	}
	kty := ecdsaKey.KeyType().String()
	crv := ecdsaKey.Crv().String()
	x := encodeToBase64RawURL(ecdsaKey.X())
	y := encodeToBase64RawURL(ecdsaKey.Y())
	return &PublicKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
		Y:   y,
	}, nil
}

func encodeToBase64RawURL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
