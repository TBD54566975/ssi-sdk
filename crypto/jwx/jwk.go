package jwx

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/x25519"
	"github.com/pkg/errors"
)

const (
	DilithiumKTY = "LWE"
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
	ALG    string `json:"alg,omitempty"`
	KID    string `json:"kid,omitempty"`
	D      string `json:"d,omitempty"`
	DP     string `json:"dp,omitempty"`
	DQ     string `json:"dq,omitempty"`
	P      string `json:"p,omitempty"`
	Q      string `json:"q,omitempty"`
	QI     string `json:"qi,omitempty"`
}

func (k *PrivateKeyJWK) IsEmpty() bool {
	if k == nil {
		return true
	}
	return reflect.DeepEqual(k, &PrivateKeyJWK{})
}

// ToPublicKeyJWK converts a PrivateKeyJWK to a PublicKeyJWK
func (k *PrivateKeyJWK) ToPublicKeyJWK() PublicKeyJWK {
	if k.ALG == "" {
		alg, err := AlgFromKeyAndCurve(k.ALG, k.CRV)
		if err == nil {
			k.ALG = alg
		}
	}
	return PublicKeyJWK{
		KTY:    k.KTY,
		CRV:    k.CRV,
		X:      k.X,
		Y:      k.Y,
		N:      k.N,
		E:      k.E,
		Use:    k.Use,
		KeyOps: k.KeyOps,
		ALG:    k.ALG,
		KID:    k.KID,
	}
}

// ToPrivateKey converts a PrivateKeyJWK to a PrivateKeyJWK
func (k *PrivateKeyJWK) ToPrivateKey() (gocrypto.PrivateKey, error) {
	if k.ALG == "" {
		alg, err := AlgFromKeyAndCurve(k.KTY, k.CRV)
		if err != nil {
			return nil, errors.Wrap(err, "getting alg from key and curve")
		}
		k.ALG = alg
	}
	if IsSupportedJWXSigningVerificationAlgorithm(k.ALG) || IsSupportedKeyAgreementType(k.ALG) {
		return k.toSupportedPrivateKey()
	}
	if IsExperimentalJWXSigningVerificationAlgorithm(k.ALG) {
		return k.toExperimentalPrivateKey()
	}
	return nil, fmt.Errorf("unsupported key conversion %+v", k)
}

func (k *PrivateKeyJWK) toSupportedPrivateKey() (gocrypto.PrivateKey, error) {
	keyBytes, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	gotJWK, err := jwk.ParseKey(keyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "creating JWK from private key")
	}
	var key gocrypto.PrivateKey
	if err = gotJWK.Raw(&key); err != nil {
		return nil, errors.Wrap(err, "converting JWK to go key")
	}

	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PrivateKey)
	}
	return key, nil
}

func (k *PrivateKeyJWK) toExperimentalPrivateKey() (gocrypto.PrivateKey, error) {
	switch k.KTY {
	case DilithiumKTY:
		return k.toDilithiumPrivateKey()
	default:
		return nil, fmt.Errorf("unsupported key type %s", k.KTY)
	}
}

// complies with https://www.ietf.org/id/draft-ietf-cose-dilithium-00.html#name-crydi-key-representations
func (k *PrivateKeyJWK) toDilithiumPrivateKey() (gocrypto.PrivateKey, error) {
	if k.D == "" {
		return nil, fmt.Errorf("missing private key D")
	}
	if k.X == "" {
		return nil, fmt.Errorf("missing public key X")
	}
	decodedPrivKey, err := base64.RawURLEncoding.DecodeString(k.D)
	if err != nil {
		return nil, err
	}
	switch k.ALG {
	case DilithiumMode2Alg.String():
		return dilithium.Mode2.PrivateKeyFromBytes(decodedPrivKey), nil
	case DilithiumMode3Alg.String():
		return dilithium.Mode3.PrivateKeyFromBytes(decodedPrivKey), nil
	case DilithiumMode5Alg.String():
		return dilithium.Mode5.PrivateKeyFromBytes(decodedPrivKey), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", k.ALG)
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
	ALG    string `json:"alg,omitempty"`
	KID    string `json:"kid,omitempty"`
}

func (k *PublicKeyJWK) IsEmpty() bool {
	if k == nil {
		return true
	}
	return reflect.DeepEqual(k, &PublicKeyJWK{})
}

// ToPublicKey converts a PublicKeyJWK to a PublicKey
func (k *PublicKeyJWK) ToPublicKey() (gocrypto.PublicKey, error) {
	if k.ALG == "" {
		alg, err := AlgFromKeyAndCurve(k.KTY, k.CRV)
		if err != nil {
			return nil, errors.Wrap(err, "getting alg from key and curve")
		}
		k.ALG = alg
	}

	if IsSupportedJWXSigningVerificationAlgorithm(k.ALG) || IsSupportedKeyAgreementType(k.ALG) {
		return k.toSupportedPublicKey()
	}
	if IsExperimentalJWXSigningVerificationAlgorithm(k.ALG) {
		return k.toExperimentalPublicKey()
	}
	return nil, fmt.Errorf("unsupported key conversion %+v", k)
}

func (k *PublicKeyJWK) toSupportedPublicKey() (gocrypto.PublicKey, error) {
	keyBytes, err := json.Marshal(k)
	if err != nil {
		return nil, err
	}
	gotJWK, err := jwk.ParseKey(keyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "creating JWK from public key")
	}
	var key gocrypto.PublicKey
	if err = gotJWK.Raw(&key); err != nil {
		return nil, errors.Wrap(err, "converting JWK to go key")
	}

	// dereference the ptr
	if reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PublicKey)
	}
	return key, nil
}

func (k *PublicKeyJWK) toExperimentalPublicKey() (gocrypto.PublicKey, error) {
	switch k.KTY {
	case DilithiumKTY:
		return k.toDilithiumPublicKey()
	default:
		return nil, fmt.Errorf("unsupported key type %s", k.KTY)
	}
}

func (k *PublicKeyJWK) toDilithiumPublicKey() (gocrypto.PublicKey, error) {
	if k.X == "" {
		return nil, fmt.Errorf("missing public key X")
	}
	decodedPubKey, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, errors.Wrap(err, "decoding public key")
	}
	switch k.ALG {
	case DilithiumMode2Alg.String():
		return dilithium.Mode2.PublicKeyFromBytes(decodedPubKey), nil
	case DilithiumMode3Alg.String():
		return dilithium.Mode3.PublicKeyFromBytes(decodedPubKey), nil
	case DilithiumMode5Alg.String():
		return dilithium.Mode5.PublicKeyFromBytes(decodedPubKey), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %s", k.ALG)
	}
}

// PublicKeyToPublicKeyJWK converts a public key to a PublicKeyJWK
func PublicKeyToPublicKeyJWK(kid *string, key gocrypto.PublicKey) (*PublicKeyJWK, error) {
	// dereference the ptr, which could be a nested ptr
	for reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PublicKey)
	}
	var pubKeyJWK *PublicKeyJWK
	var err error
	switch k := key.(type) {
	case rsa.PublicKey:
		pubKeyJWK, err = jwkFromRSAPublicKey(k)
	case ed25519.PublicKey:
		pubKeyJWK, err = jwkFromEd25519PublicKey(k)
	case x25519.PublicKey:
		pubKeyJWK, err = jwkFromX25519PublicKey(k)
	case secp256k1.PublicKey:
		pubKeyJWK, err = jwkFromSECP256k1PublicKey(k)
	case ecdsa.PublicKey:
		pubKeyJWK, err = jwkFromECDSAPublicKey(k)
	case mode2.PublicKey:
		pubKey := dilithium.Mode2.PublicKeyFromBytes(k.Bytes())
		pubKeyJWK, err = jwkFromDilithiumPublicKey(dilithium.Mode2, pubKey)
	case mode3.PublicKey:
		pubKey := dilithium.Mode3.PublicKeyFromBytes(k.Bytes())
		pubKeyJWK, err = jwkFromDilithiumPublicKey(dilithium.Mode3, pubKey)
	case mode5.PublicKey:
		pubKey := dilithium.Mode5.PublicKeyFromBytes(k.Bytes())
		pubKeyJWK, err = jwkFromDilithiumPublicKey(dilithium.Mode5, pubKey)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", k)
	}
	if err != nil {
		return nil, err
	}
	if kid != nil {
		pubKeyJWK.KID = *kid
	}
	if pubKeyJWK.ALG == "" {
		alg, err := AlgFromKeyAndCurve(pubKeyJWK.KTY, pubKeyJWK.CRV)
		if err != nil {
			return nil, errors.Wrap(err, "getting alg from key and curve")
		}
		pubKeyJWK.ALG = alg
	}
	return pubKeyJWK, err
}

// PrivateKeyToPrivateKeyJWK converts a private key to a PrivateKeyJWK
func PrivateKeyToPrivateKeyJWK(keyID *string, key gocrypto.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	// dereference the ptr, which could be nested
	for reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PrivateKey)
	}
	var pubKeyJWK *PublicKeyJWK
	var privKeyJWK *PrivateKeyJWK
	var err error
	switch k := key.(type) {
	case rsa.PrivateKey:
		pubKeyJWK, privKeyJWK, err = jwkFromRSAPrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
	case ed25519.PrivateKey:
		pubKeyJWK, privKeyJWK, err = jwkFromEd25519PrivateKey(k)
	case x25519.PrivateKey:
		pubKeyJWK, privKeyJWK, err = jwkFromX25519PrivateKey(k)
	case secp256k1.PrivateKey:
		pubKeyJWK, privKeyJWK, err = jwkFromSECP256k1PrivateKey(k)
	case ecdsa.PrivateKey:
		if k.Curve == elliptic.P224() {
			return nil, nil, fmt.Errorf("unsupported curve: %s", k.Curve.Params().Name)
		}
		pubKeyJWK, privKeyJWK, err = jwkFromECDSAPrivateKey(k)
	case mode2.PrivateKey:
		privKey := dilithium.Mode2.PrivateKeyFromBytes(k.Bytes())
		pubKeyJWK, privKeyJWK, err = jwkFromDilithiumPrivateKey(dilithium.Mode2, privKey)
	case mode3.PrivateKey:
		privKey := dilithium.Mode3.PrivateKeyFromBytes(k.Bytes())
		pubKeyJWK, privKeyJWK, err = jwkFromDilithiumPrivateKey(dilithium.Mode3, privKey)
	case mode5.PrivateKey:
		privKey := dilithium.Mode5.PrivateKeyFromBytes(k.Bytes())
		pubKeyJWK, privKeyJWK, err = jwkFromDilithiumPrivateKey(dilithium.Mode5, privKey)
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %T", k)
	}
	if err != nil {
		return nil, nil, err
	}
	if keyID != nil {
		pubKeyJWK.KID = *keyID
		privKeyJWK.KID = *keyID
	}
	if privKeyJWK.ALG == "" {
		alg, err := AlgFromKeyAndCurve(privKeyJWK.KTY, privKeyJWK.CRV)
		if err != nil {
			return nil, nil, errors.Wrap(err, "getting alg from key and curve")
		}
		pubKeyJWK.ALG = alg
		privKeyJWK.ALG = alg
	}
	return pubKeyJWK, privKeyJWK, nil
}

// jwkFromRSAPrivateKey converts a RSA private key to a JWK
func jwkFromRSAPrivateKey(key rsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	rsaJWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating rsa jwk")
	}
	rsaJWKBytes, err := json.Marshal(rsaJWKGeneric)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling rsa jwk")
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

// jwkFromRSAPublicKey converts an RSA public key to a JWK
func jwkFromRSAPublicKey(key rsa.PublicKey) (*PublicKeyJWK, error) {
	rsaJWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating rsa jwk")
	}
	if err = jwk.AssignKeyID(rsaJWKGeneric); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
	}
	rsaJWKBytes, err := json.Marshal(rsaJWKGeneric)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling rsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(rsaJWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling rsa jwk")
	}
	return &publicKeyJWK, nil
}

// jwkFromEd25519PrivateKey converts an Ed25519 private key to a JWK
func jwkFromEd25519PrivateKey(key ed25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating ed25519 jwk")
	}
	if err = jwk.AssignKeyID(ed25519JWKGeneric); err != nil {
		return nil, nil, errors.Wrap(err, "assigning jwk kid")
	}
	ed25519JWKBytes, err := json.Marshal(ed25519JWKGeneric)
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

// jwkFromEd25519PublicKey converts a Ed25519 public key to a JWK
func jwkFromEd25519PublicKey(key ed25519.PublicKey) (*PublicKeyJWK, error) {
	ed25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ed25519 jwk")
	}
	if err = jwk.AssignKeyID(ed25519JWKGeneric); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
	}
	x25519JWKBytes, err := json.Marshal(ed25519JWKGeneric)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling ed25519 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(x25519JWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	return &publicKeyJWK, nil
}

// jwkFromX25519PrivateKey converts a X25519 private key to a JWK
func jwkFromX25519PrivateKey(key x25519.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	x25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating x25519 jwk")
	}
	if err = jwk.AssignKeyID(x25519JWKGeneric); err != nil {
		return nil, nil, errors.Wrap(err, "assigning jwk kid")
	}
	x25519JWKBytes, err := json.Marshal(x25519JWKGeneric)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling ed25519 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(x25519JWKBytes, &publicKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	var privateKeyJWK PrivateKeyJWK
	if err = json.Unmarshal(x25519JWKBytes, &privateKeyJWK); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshalling ed25519 jwk")
	}
	return &publicKeyJWK, &privateKeyJWK, nil
}

// jwkFromX25519PublicKey converts a X25519 public key to a JWK
func jwkFromX25519PublicKey(key x25519.PublicKey) (*PublicKeyJWK, error) {
	x25519JWKGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating x25519 jwk")
	}
	if err = jwk.AssignKeyID(x25519JWKGeneric); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
	}
	x25519JWKBytes, err := json.Marshal(x25519JWKGeneric)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling x25519 jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(x25519JWKBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling x25519 jwk")
	}
	return &publicKeyJWK, nil
}

// jwkFromSECP256k1PrivateKey converts a SECP256k1 private key to a JWK
func jwkFromSECP256k1PrivateKey(key secp256k1.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaPrivKey := key.ToECDSA()
	secp256k1JWKGeneric, err := jwk.FromRaw(ecdsaPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating secp256k1 jwk")
	}
	if err = jwk.AssignKeyID(secp256k1JWKGeneric); err != nil {
		return nil, nil, errors.Wrap(err, "assigning jwk kid")
	}
	secp256k1JWKBytes, err := json.Marshal(secp256k1JWKGeneric)
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

// jwkFromSECP256k1PublicKey converts a SECP256k1 public key to a JWK
func jwkFromSECP256k1PublicKey(key secp256k1.PublicKey) (*PublicKeyJWK, error) {
	ecdsaPubKey := key.ToECDSA()
	secp256k1JWK, err := jwk.FromRaw(ecdsaPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "generating secp256k1 jwk")
	}
	if err = jwk.AssignKeyID(secp256k1JWK); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
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

// jwkFromECDSAPrivateKey converts a ECDSA private key to a JWK
func jwkFromECDSAPrivateKey(key ecdsa.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating ecdsa jwk")
	}
	if err = jwk.AssignKeyID(ecdsaKeyGeneric); err != nil {
		return nil, nil, errors.Wrap(err, "assigning jwk kid")
	}
	ecdsaKeyBytes, err := json.Marshal(ecdsaKeyGeneric)
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

// as per https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-00.html
func jwkFromDilithiumPrivateKey(m dilithium.Mode, k dilithium.PrivateKey) (*PublicKeyJWK, *PrivateKeyJWK, error) {
	var alg jwa.SignatureAlgorithm
	switch m {
	case dilithium.Mode2:
		alg = DilithiumMode2Alg
	case dilithium.Mode3:
		alg = DilithiumMode3Alg
	case dilithium.Mode5:
		alg = DilithiumMode5Alg
	}

	// serialize pub and priv keys to b64url
	privKeyBytes := k.Bytes()
	d := base64.RawURLEncoding.EncodeToString(privKeyBytes)
	publicKey := k.Public().(dilithium.PublicKey)
	pubKeyBytes := publicKey.Bytes()
	x := base64.RawURLEncoding.EncodeToString(pubKeyBytes)
	privKeyJWK := PrivateKeyJWK{
		KTY: DilithiumKTY,
		X:   x,
		ALG: alg.String(),
		D:   d,
	}
	pubKeyJWK := privKeyJWK.ToPublicKeyJWK()
	return &pubKeyJWK, &privKeyJWK, nil
}

// jwkFromECDSAPublicKey converts a ECDSA public key to a JWK
func jwkFromECDSAPublicKey(key ecdsa.PublicKey) (*PublicKeyJWK, error) {
	ecdsaKeyGeneric, err := jwk.FromRaw(key)
	if err != nil {
		return nil, errors.Wrap(err, "generating ecdsa jwk")
	}
	if err = jwk.AssignKeyID(ecdsaKeyGeneric); err != nil {
		return nil, errors.Wrap(err, "assigning jwk kid")
	}
	ecdsaKeyBytes, err := json.Marshal(ecdsaKeyGeneric)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling ecdsa jwk")
	}
	var publicKeyJWK PublicKeyJWK
	if err = json.Unmarshal(ecdsaKeyBytes, &publicKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling ecdsa jwk")
	}
	return &publicKeyJWK, nil
}

func jwkFromDilithiumPublicKey(mode dilithium.Mode, k dilithium.PublicKey) (*PublicKeyJWK, error) {
	var alg jwa.SignatureAlgorithm
	switch mode {
	case dilithium.Mode2:
		alg = DilithiumMode2Alg
	case dilithium.Mode3:
		alg = DilithiumMode3Alg
	case dilithium.Mode5:
		alg = DilithiumMode5Alg
	}

	// serialize pub and priv keys to b64url
	pubKeyBytes := k.Bytes()
	x := base64.RawURLEncoding.EncodeToString(pubKeyBytes)
	return &PublicKeyJWK{
		KTY: DilithiumKTY,
		X:   x,
		ALG: alg.String(),
	}, nil
}
