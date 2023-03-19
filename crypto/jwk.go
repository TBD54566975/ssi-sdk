package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strconv"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/x25519"
	"github.com/pkg/errors"
)

// PrivateKeyJWK complies with RFC7517 https://datatracker.ietf.org/doc/html/rfc7517
type PrivateKeyJWK struct {
	KTY    string `json:"kty,omitempty" validate:"required"`
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
	KTY    string `json:"kty,omitempty" validate:"required"`
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
	if err = json.Unmarshal(keyBytes, &pubKeyJWK); err != nil {
		return nil, err
	}
	return &pubKeyJWK, nil
}

// JWKFromPublicKeyJWK converts a PublicKeyJWK to a JWK
func JWKFromPublicKeyJWK(key PublicKeyJWK) (jwk.Key, error) {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return jwk.ParseKey(keyBytes)
}

// JWKFromPrivateKeyJWK converts a PrivateKeyJWK to a JWK
func JWKFromPrivateKeyJWK(key PrivateKeyJWK) (jwk.Key, error) {
	keyBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	return jwk.ParseKey(keyBytes)
}

// PublicKeyToJWK converts a public key to a JWK
func PublicKeyToJWK(key crypto.PublicKey) (jwk.Key, error) {
	switch k := key.(type) {
	case rsa.PublicKey:
		return jwkKeyFromRSAPublicKey(k)
	case *rsa.PublicKey:
		return jwkKeyFromRSAPublicKey(*k)
	case ed25519.PublicKey:
		return jwkKeyFromEd25519PublicKey(k)
	case *ed25519.PublicKey:
		return jwkKeyFromEd25519PublicKey(*k)
	case x25519.PublicKey:
		return jwkKeyFromX25519PublicKey(k)
	case *x25519.PublicKey:
		return jwkKeyFromX25519PublicKey(*k)
	case secp256k1.PublicKey:
		return jwkKeyFromSECP256k1PublicKey(k)
	case *secp256k1.PublicKey:
		return jwkKeyFromSECP256k1PublicKey(*k)
	case ecdsa.PublicKey:
		return jwkKeyFromECDSAPublicKey(k)
	case *ecdsa.PublicKey:
		return jwkKeyFromECDSAPublicKey(*k)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", k)
	}
}

// PublicKeyToPublicKeyJWK converts a public key to a PublicKeyJWK
func PublicKeyToPublicKeyJWK(key crypto.PublicKey) (*PublicKeyJWK, error) {
	switch k := key.(type) {
	case rsa.PublicKey:
		return jwkFromRSAPublicKey(k)
	case *rsa.PublicKey:
		return jwkFromRSAPublicKey(*k)
	case ed25519.PublicKey:
		return jwkFromEd25519PublicKey(k)
	case *ed25519.PublicKey:
		return jwkFromEd25519PublicKey(*k)
	case x25519.PublicKey:
		return jwkFromX25519PublicKey(k)
	case *x25519.PublicKey:
		return jwkFromX25519PublicKey(*k)
	case secp256k1.PublicKey:
		return jwkFromSECP256k1PublicKey(k)
	case *secp256k1.PublicKey:
		return jwkFromSECP256k1PublicKey(*k)
	case ecdsa.PublicKey:
		return jwkFromECDSAPublicKey(k)
	case *ecdsa.PublicKey:
		return jwkFromECDSAPublicKey(*k)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", k)
	}
}

// PrivateKeyToJWK converts a private key to a JWK
func PrivateKeyToJWK(key crypto.PrivateKey) (jwk.Key, error) {
	switch k := key.(type) {
	case rsa.PrivateKey:
		return jwkKeyFromRSAPrivateKey(k)
	case *rsa.PrivateKey:
		return jwkKeyFromRSAPrivateKey(*k)
	case ed25519.PrivateKey:
		return jwkKeyFromEd25519PrivateKey(k)
	case *ed25519.PrivateKey:
		return jwkKeyFromEd25519PrivateKey(*k)
	case x25519.PrivateKey:
		return jwkKeyFromX25519PrivateKey(k)
	case *x25519.PrivateKey:
		return jwkKeyFromX25519PrivateKey(*k)
	case secp256k1.PrivateKey:
		return jwkKeyFromSECP256k1PrivateKey(k)
	case *secp256k1.PrivateKey:
		return jwkKeyFromSECP256k1PrivateKey(*k)
	case ecdsa.PrivateKey:
		return jwkKeyFromECDSAPrivateKey(k)
	case *ecdsa.PrivateKey:
		return jwkKeyFromECDSAPrivateKey(*k)
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", k)
	}
}

// PrivateKeyToPrivateKeyJWK converts a private key to a PrivateKeyJWK
func PrivateKeyToPrivateKeyJWK(key crypto.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	switch k := key.(type) {
	case rsa.PrivateKey:
		return jwkFromRSAPrivateKey(k)
	case ed25519.PrivateKey:
		return jwkFromEd25519PrivateKey(k)
	case x25519.PrivateKey:
		return jwkFromX25519PrivateKey(k)
	case secp256k1.PrivateKey:
		return jwkFromSECP256k1PrivateKey(k)
	case ecdsa.PrivateKey:
		return jwkFromECDSAPrivateKey(k)
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %T", k)
	}
}

// jwkKeyFromRSAPrivateKey converts a RSA private key to a JWK
func jwkKeyFromRSAPrivateKey(key rsa.PrivateKey) (jwk.Key, error) {
	rsaJWK, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate rsa jwk")
	}
	return rsaJWK, nil
}

// jwkFromRSAPrivateKey converts a RSA private key to a JWK
func jwkFromRSAPrivateKey(key rsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	rsaJWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate rsa jwk")
	}
	rsaJWK, ok := rsaJWKGeneric.(jwk.RSAPrivateKey)
	if !ok {
		return nil, nil, errors.New("failed to cast rsa jwk")
	}

	kty := rsaJWK.KeyType().String()

	n := encodeToBase64RawURL(key.N.Bytes())
	e := encodeToBase64RawURL([]byte(strconv.Itoa(key.E)))

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

// jwkKeyFromRSAPublicKey converts an RSA public key to a JWK
func jwkKeyFromRSAPublicKey(key rsa.PublicKey) (jwk.Key, error) {
	rsaJWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate rsa jwk")
	}
	rsaJWK, ok := rsaJWKGeneric.(jwk.RSAPublicKey)
	if !ok {
		return nil, errors.New("failed to cast rsa jwk")
	}
	return rsaJWK, nil
}

// jwkFromRSAPublicKey converts an RSA public key to a JWK
func jwkFromRSAPublicKey(key rsa.PublicKey) (*PublicKeyJWK, error) {
	rsaJWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate rsa jwk")
	}
	rsaJWK, ok := rsaJWKGeneric.(jwk.RSAPublicKey)
	if !ok {
		return nil, errors.New("failed to cast rsa jwk")
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

// jwkKeyFromEd25519PrivateKey converts an Ed25519 private key to a JWK
func jwkKeyFromEd25519PrivateKey(key ed25519.PrivateKey) (jwk.Key, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate ed25519 jwk")
	}
	ed25519JWK, ok := ed25519JWKGeneric.(jwk.OKPPrivateKey)
	if !ok {
		return nil, errors.New("failed to cast ed25519 jwk")
	}
	return ed25519JWK, nil
}

// jwkFromEd25519PrivateKey converts an Ed25519 private key to a JWK
func jwkFromEd25519PrivateKey(key ed25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate ed25519 jwk")
	}
	ed25519JWK, ok := ed25519JWKGeneric.(jwk.OKPPrivateKey)
	if !ok {
		return nil, nil, errors.New("failed to cast ed25519 jwk")
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

// jwkKeyFromEd25519PublicKey converts a Ed25519 public key to a JWK
func jwkKeyFromEd25519PublicKey(key ed25519.PublicKey) (jwk.Key, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate ed25519 jwk")
	}
	ed25519JWK, ok := ed25519JWKGeneric.(jwk.OKPPublicKey)
	if !ok {
		return nil, errors.New("failed to cast ed25519 jwk")
	}
	return ed25519JWK, nil
}

// jwkFromEd25519PublicKey converts a Ed25519 public key to a JWK
func jwkFromEd25519PublicKey(key ed25519.PublicKey) (*PublicKeyJWK, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate ed25519 jwk")
	}
	ed25519JWK, ok := ed25519JWKGeneric.(jwk.OKPPublicKey)
	if !ok {
		return nil, errors.New("failed to cast ed25519 jwk")
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
func jwkKeyFromX25519PrivateKey(key x25519.PrivateKey) (jwk.Key, error) {
	return jwkKeyFromEd25519PrivateKey(ed25519.PrivateKey(key))
}

// jwkFromX25519PrivateKey converts a X25519 private key to a JWK
func jwkFromX25519PrivateKey(key x25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	return jwkFromEd25519PrivateKey(ed25519.PrivateKey(key))
}

// jwkKeyFromX25519PublicKey converts a X25519 public key to a JWK
func jwkKeyFromX25519PublicKey(key x25519.PublicKey) (jwk.Key, error) {
	return jwkKeyFromEd25519PublicKey(ed25519.PublicKey(key))
}

// jwkFromX25519PublicKey converts a X25519 public key to a JWK
func jwkFromX25519PublicKey(key x25519.PublicKey) (*PublicKeyJWK, error) {
	return jwkFromEd25519PublicKey(ed25519.PublicKey(key))
}

// jwkKeyFromSECP256k1PrivateKey converts a SECP256k1 private key to a JWK
func jwkKeyFromSECP256k1PrivateKey(key secp256k1.PrivateKey) (jwk.Key, error) {
	ecdsaPrivKey := key.ToECDSA()
	secp256k1JWKGeneric, err := jwk.FromRaw(ecdsaPrivKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate secp256k1 jwk")
	}
	secp256k1JWK, ok := secp256k1JWKGeneric.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("failed to cast secp256k1 jwk")
	}
	return secp256k1JWK, nil
}

// jwkFromSECP256k1PrivateKey converts a SECP256k1 private key to a JWK
func jwkFromSECP256k1PrivateKey(key secp256k1.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaPrivKey := key.ToECDSA()
	secp256k1JWKGeneric, err := jwk.FromRaw(ecdsaPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate secp256k1 jwk")
	}
	secp256k1JWK, ok := secp256k1JWKGeneric.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, nil, errors.New("failed to cast secp256k1 jwk")
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

// jwkKeyFromSECP256k1PublicKey converts a SECP256k1 public key to a JWK
func jwkKeyFromSECP256k1PublicKey(key secp256k1.PublicKey) (jwk.Key, error) {
	ecdsaPubKey := key.ToECDSA()
	secp256k1JWKGeneric, err := jwk.FromRaw(ecdsaPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate secp256k1 jwk")
	}
	secp256k1JWK, ok := secp256k1JWKGeneric.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, errors.New("failed to cast secp256k1 jwk")
	}
	return secp256k1JWK, nil
}

// jwkFromSECP256k1PublicKey converts a SECP256k1 public key to a JWK
func jwkFromSECP256k1PublicKey(key secp256k1.PublicKey) (*PublicKeyJWK, error) {
	ecdsaPubKey := key.ToECDSA()
	secp256k1JWK, err := jwk.FromRaw(ecdsaPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate secp256k1 jwk")
	}
	secp256k1JWK, ok := secp256k1JWK.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, errors.New("failed to cast secp256k1 jwk")
	}

	kty := secp256k1JWK.KeyType().String()
	maybeCRV, ok := secp256k1JWK.Get(jwk.ECDSACrvKey)
	if !ok {
		return nil, errors.New("failed to get crv from secp256k1 jwk")
	}
	crv := maybeCRV.(jwa.EllipticCurveAlgorithm).String()
	maybeX, ok := secp256k1JWK.Get(jwk.ECDSAXKey)
	if !ok {
		return nil, errors.New("failed to get x from secp256k1 jwk")
	}
	x := encodeToBase64RawURL(maybeX.([]byte))
	maybeY, ok := secp256k1JWK.Get(jwk.ECDSAYKey)
	if !ok {
		return nil, errors.New("failed to get y from secp256k1 jwk")
	}
	y := encodeToBase64RawURL(maybeY.([]byte))
	return &PublicKeyJWK{
		KTY: kty,
		CRV: crv,
		X:   x,
		Y:   y,
	}, nil
}

// jwkKeyFromECDSAPrivateKey converts a ECDSA private key to a JWK
func jwkKeyFromECDSAPrivateKey(key ecdsa.PrivateKey) (jwk.Key, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate ecdsa jwk")
	}
	ecdsaKey, ok := ecdsaKeyGeneric.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("failed to cast ecdsa jwk")
	}
	return ecdsaKey, nil
}

// jwkFromECDSAPrivateKey converts a ECDSA private key to a JWK
func jwkFromECDSAPrivateKey(key ecdsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate ecdsa jwk")
	}
	ecdsaKey, ok := ecdsaKeyGeneric.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, nil, errors.New("failed to cast ecdsa jwk")
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

// jwkKeyFromECDSAPublicKey converts a ECDSA public key to a JWK
func jwkKeyFromECDSAPublicKey(key ecdsa.PublicKey) (jwk.Key, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate ecdsa jwk")
	}
	ecdsaKey, ok := ecdsaKeyGeneric.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, errors.New("failed to cast ecdsa jwk")
	}
	return ecdsaKey, nil
}

// jwkFromECDSAPublicKey converts a ECDSA public key to a JWK
func jwkFromECDSAPublicKey(key ecdsa.PublicKey) (*PublicKeyJWK, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate ecdsa jwk")
	}
	ecdsaKey, ok := ecdsaKeyGeneric.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, errors.New("failed to cast ecdsa jwk")
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
