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

// ToPublicKeyJWK converts a PrivateKeyJWK to a PublicKeyJWK
func (k PrivateKeyJWK) ToPublicKeyJWK() PublicKeyJWK {
	return PublicKeyJWK{
		KTY:    k.KTY,
		CRV:    k.CRV,
		X:      k.X,
		Y:      k.Y,
		N:      k.N,
		E:      k.E,
		Use:    k.Use,
		KeyOps: k.KeyOps,
		Alg:    k.Alg,
		KID:    k.KID,
	}
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
		return nil, errors.Wrap(err, "generating rsa jwk")
	}
	return rsaJWK, nil
}

// jwkFromRSAPrivateKey converts a RSA private key to a JWK
func jwkFromRSAPrivateKey(key rsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	rsaJWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating rsa jwk")
	}
	rsaJWK, ok := rsaJWKGeneric.(jwk.RSAPrivateKey)
	if !ok {
		return nil, nil, errors.New("failed casting to rsa jwk")
	}

	rsaJWKBytes, err := json.Marshal(rsaJWK)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to marshal rsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(rsaJWKBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling rsa public jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(rsaJWKBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling rsa private jwk")
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
		return nil, errors.New("failed casting to rsa jwk")
	}
	return rsaJWK, nil
}

// jwkFromRSAPublicKey converts an RSA public key to a JWK
func jwkFromRSAPublicKey(key rsa.PublicKey) (*PublicKeyJWK, error) {
	rsaJWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating rsa jwk")
	}
	rsaJWK, ok := rsaJWKGeneric.(jwk.RSAPublicKey)
	if !ok {
		return nil, errors.New("failed casting to rsa jwk")
	}

	rsaJWKBytes, err := json.Marshal(rsaJWK)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling rsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(rsaJWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling rsa jwk")
	}
	return &publicKeyJWK, nil
}

// jwkKeyFromEd25519PrivateKey converts an Ed25519 private key to a JWK
func jwkKeyFromEd25519PrivateKey(key ed25519.PrivateKey) (jwk.Key, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ed25519 jwk")
	}
	ed25519JWK, ok := ed25519JWKGeneric.(jwk.OKPPrivateKey)
	if !ok {
		return nil, errors.New("failed casting ed25519 jwk")
	}
	return ed25519JWK, nil
}

// jwkFromEd25519PrivateKey converts an Ed25519 private key to a JWK
func jwkFromEd25519PrivateKey(key ed25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating ed25519 jwk")
	}
	ed25519JWK, ok := ed25519JWKGeneric.(jwk.OKPPrivateKey)
	if !ok {
		return nil, nil, errors.New("failed casting ed25519 jwk")
	}

	ed25519JWKBytes, err := json.Marshal(ed25519JWK)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling ed25519 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(ed25519JWKBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(ed25519JWKBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkKeyFromEd25519PublicKey converts a Ed25519 public key to a JWK
func jwkKeyFromEd25519PublicKey(key ed25519.PublicKey) (jwk.Key, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ed25519 jwk")
	}
	ed25519JWK, ok := ed25519JWKGeneric.(jwk.OKPPublicKey)
	if !ok {
		return nil, errors.New("failed casting to ed25519 jwk")
	}
	return ed25519JWK, nil
}

// jwkFromEd25519PublicKey converts a Ed25519 public key to a JWK
func jwkFromEd25519PublicKey(key ed25519.PublicKey) (*PublicKeyJWK, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ed25519 jwk")
	}
	ed25519JWK, ok := ed25519JWKGeneric.(jwk.OKPPublicKey)
	if !ok {
		return nil, errors.New("failed casting to ed25519 jwk")
	}

	ed25519JWKBytes, err := json.Marshal(ed25519JWK)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling ed25519 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(ed25519JWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	return &publicKeyJWK, nil
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
		return nil, errors.Wrap(err, "generating secp256k1 jwk")
	}
	secp256k1JWK, ok := secp256k1JWKGeneric.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("failed casting to secp256k1 jwk")
	}
	return secp256k1JWK, nil
}

// jwkFromSECP256k1PrivateKey converts a SECP256k1 private key to a JWK
func jwkFromSECP256k1PrivateKey(key secp256k1.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaPrivKey := key.ToECDSA()
	secp256k1JWKGeneric, err := jwk.FromRaw(ecdsaPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating secp256k1 jwk")
	}
	secp256k1JWK, ok := secp256k1JWKGeneric.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, nil, errors.New("failed casting to secp256k1 jwk")
	}

	secp256k1JWKBytes, err := json.Marshal(secp256k1JWK)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling secp256k1 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(secp256k1JWKBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling secp256k1 public jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(secp256k1JWKBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling secp256k1 private jwk")
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkKeyFromSECP256k1PublicKey converts a SECP256k1 public key to a JWK
func jwkKeyFromSECP256k1PublicKey(key secp256k1.PublicKey) (jwk.Key, error) {
	ecdsaPubKey := key.ToECDSA()
	secp256k1JWKGeneric, err := jwk.FromRaw(ecdsaPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "generating secp256k1 jwk")
	}
	secp256k1JWK, ok := secp256k1JWKGeneric.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, errors.New("failed casting to secp256k1 jwk")
	}
	return secp256k1JWK, nil
}

// jwkFromSECP256k1PublicKey converts a SECP256k1 public key to a JWK
func jwkFromSECP256k1PublicKey(key secp256k1.PublicKey) (*PublicKeyJWK, error) {
	ecdsaPubKey := key.ToECDSA()
	secp256k1JWK, err := jwk.FromRaw(ecdsaPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "generating secp256k1 jwk")
	}
	secp256k1JWK, ok := secp256k1JWK.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, errors.New("failed casting to secp256k1 jwk")
	}

	secp256k1JWKBytes, err := json.Marshal(secp256k1JWK)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling secp256k1 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(secp256k1JWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling secp256k1 jwk")
	}
	return &publicKeyJWK, nil
}

// jwkKeyFromECDSAPrivateKey converts a ECDSA private key to a JWK
func jwkKeyFromECDSAPrivateKey(key ecdsa.PrivateKey) (jwk.Key, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ecdsa jwk")
	}
	ecdsaKey, ok := ecdsaKeyGeneric.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, errors.New("failed casting to ecdsa jwk")
	}
	return ecdsaKey, nil
}

// jwkFromECDSAPrivateKey converts a ECDSA private key to a JWK
func jwkFromECDSAPrivateKey(key ecdsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating ecdsa jwk")
	}
	ecdsaKey, ok := ecdsaKeyGeneric.(jwk.ECDSAPrivateKey)
	if !ok {
		return nil, nil, errors.New("failed casting to ecdsa jwk")
	}

	ecdsaKeyBytes, err := json.Marshal(ecdsaKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling ecdsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(ecdsaKeyBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ecdsa public jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(ecdsaKeyBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ecdsa private jwk")
	}

	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkKeyFromECDSAPublicKey converts a ECDSA public key to a JWK
func jwkKeyFromECDSAPublicKey(key ecdsa.PublicKey) (jwk.Key, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ecdsa jwk")
	}
	ecdsaKey, ok := ecdsaKeyGeneric.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, errors.New("failed casting to ecdsa jwk")
	}
	return ecdsaKey, nil
}

// jwkFromECDSAPublicKey converts a ECDSA public key to a JWK
func jwkFromECDSAPublicKey(key ecdsa.PublicKey) (*PublicKeyJWK, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ecdsa jwk")
	}
	ecdsaKey, ok := ecdsaKeyGeneric.(jwk.ECDSAPublicKey)
	if !ok {
		return nil, errors.New("failed casting to ecdsa jwk")
	}

	ecdsaKeyBytes, err := json.Marshal(ecdsaKey)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling ecdsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(ecdsaKeyBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling ecdsa jwk")
	}
	return &publicKeyJWK, nil
}

func encodeToBase64RawURL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
