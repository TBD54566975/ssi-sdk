package cryptosuite

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/TBD54566975/did-sdk/util"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/pkg/errors"
)

type (
	KTY string
	CRV string
	ALG string
)

const (
	JsonWebKey2020 string = "JsonWebKey2020"

	// Supported key types

	OKP KTY = "OKP"
	EC  KTY = "EC"
	RSA KTY = "RSA"

	// Supported curves

	Ed25519   CRV = "Ed25519"
	X25519    CRV = "X25519"
	SECP256k1 CRV = "secp256k1"
	P256      CRV = "P-256"
	P384      CRV = "P-384"

	// Supported signing algs

	EdDSA  ALG = "EdDSA"
	ES256K ALG = "ES256K"
	PS256  ALG = "PS256"
	PS384  ALG = "PS384"
	RS256  ALG = "RS256"

	// Known key sizes

	RSAKeySize       int = 2048
	SECP256k1KeySize int = 32
	P256KeySize      int = 32
	P384KeySize      int = 48
)

// TODO(gabe) use this everywhere
type JSONWebKey2020 struct {
	ID            string `json:"id,omitempty"`
	Type          string `json:"type,omitempty"`
	Controller    string `json:"controller,omitempty"`
	PrivateKeyJWK `json:"privateKeyJwk,omitempty"`
	PublicKeyJWK  `json:"publicKeyJwk,omitempty"`
}

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

type JSONWebKey interface {
	Generate() error
	ToJSONWebKey2020(privKey []byte) error

	ToPublicKey() (crypto.PublicKey, error)
	ToPrivateKey() (crypto.PrivateKey, error)
}

// GenerateJSONWebKey2020 The JSONWebKey2020 type specifies a number of key type and curve pairs to enable JOSE conformance
// these pairs are supported in this library and generated via the function below
// https://w3c-ccg.github.io/lds-jws2020/#dfn-jsonwebkey2020
func GenerateJSONWebKey2020(kty KTY, crv *CRV) (*JSONWebKey2020, error) {
	if kty == RSA {
		return GenerateRSAJSONWebKey2020()
	}
	if crv == nil {
		return nil, errors.New("crv must be specified for non-RSA key types")
	}
	curve := *crv
	if kty == OKP {
		switch curve {
		case Ed25519:
			return GenerateEd25519JSONWebKey2020()
		case X25519:
			return GenerateX25519JSONWebKey2020()
		default:
			return nil, fmt.Errorf("unsupported OKP curve: %s", curve)
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
			return nil, fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return nil, fmt.Errorf("unsupported key type: %s", kty)
}

func GenerateRSAJSONWebKey2020() (*JSONWebKey2020, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return nil, err
	}
	rsaJWK := jwk.NewRSAPrivateKey()
	if err := rsaJWK.FromRaw(privateKey); err != nil {
		return nil, err
	}
	kty := rsaJWK.KeyType().String()
	n := encodeToBase64RawURL(rsaJWK.N())
	e := encodeToBase64RawURL(rsaJWK.E())
	return &JSONWebKey2020{
		Type: JsonWebKey2020,
		PrivateKeyJWK: PrivateKeyJWK{
			KTY: kty,
			N:   n,
			E:   e,
			D:   encodeToBase64RawURL(rsaJWK.D()),
			DP:  encodeToBase64RawURL(rsaJWK.DP()),
			DQ:  encodeToBase64RawURL(rsaJWK.DQ()),
			P:   encodeToBase64RawURL(rsaJWK.P()),
			Q:   encodeToBase64RawURL(rsaJWK.Q()),
			QI:  encodeToBase64RawURL(rsaJWK.QI()),
		},
		PublicKeyJWK: PublicKeyJWK{
			KTY: kty,
			N:   n,
			E:   e,
		},
	}, nil
}

func GenerateEd25519JSONWebKey2020() (*ed25519.PrivateKey, *PublicKeyJWK, error) {
	pubKey, privKey, err := util.GenerateEd25519Key()
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK, err := PublicEd25519JSONWebKey2020(pubKey)
	if err != nil {
		return nil, nil, err
	}
	return &privKey, pubKeyJWK, nil
}

func GenerateX25519JSONWebKey2020() (*ed25519.PrivateKey, *PublicKeyJWK, error) {
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
	return &privKey, pubKeyJWK, nil
}

func GenerateSECP256k1JSONWebKey2020() (*secp.PrivateKey, *PublicKeyJWK, error) {
	// We use the secp256k1 implementation from Decred https://github.com/decred/dcrd
	// which is utilized in the widely accepted go bitcoin node implementation from the btcsuite project
	// https://github.com/btcsuite/btcd/blob/master/btcec/btcec.go#L23
	privKey, err := secp.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	pubKey := privKey.PubKey()
	pubKeyJWK, err := SECP256k1JSONWebKey2020(*pubKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKeyJWK, nil
}

func GenerateP256JSONWebKey2020() (*ecdsa.PrivateKey, *PublicKeyJWK, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK, err := P256JSONWebKey2020(privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKeyJWK, nil
}

func GenerateP384JSONWebKey2020() (*ecdsa.PrivateKey, *PublicKeyJWK, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK, err := P384JSONWebKey2020(privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKeyJWK, nil
}

type JSONWebKeySigner struct {
	jwa.SignatureAlgorithm
	jwk.Key
}

func (s JSONWebKeySigner) KeyID() string {
	return s.Key.KeyID()
}

func (s JSONWebKeySigner) KeyType() string {
	return string(s.Key.KeyType())
}

func (s JSONWebKeySigner) SigningAlgorithm() string {
	return s.Algorithm()
}

func (s JSONWebKeySigner) Sign(tbs []byte) ([]byte, error) {
	headers := jws.NewHeaders()
	if err := headers.Set("b64", false); err != nil {
		return nil, err
	}
	if err := headers.Set("crit", "b64"); err != nil {
		return nil, err
	}
	signOptions := []jws.SignOption{jws.WithHeaders(headers), jws.WithDetachedPayload(tbs)}
	return jws.Sign(nil, jwa.EdDSA, s.Key, signOptions...)
}

func NewJSONWebKeySigner(key PrivateKeyJWK) (*JSONWebKeySigner, error) {
	if key.KID == "" {
		return nil, errors.New("key must have an `kid` value")
	}
	privKeyJWKBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	privKeyJWK, err := jwk.ParseKey(privKeyJWKBytes)
	if err != nil {
		return nil, err
	}
	var crv string
	if maybeCrv, b := privKeyJWK.Get("crv"); b {
		if strCrv, ok := maybeCrv.(string); ok {
			crv = strCrv
		}
		return nil, fmt.Errorf("could not get curve value: %+v", maybeCrv)
	}
	alg, err := AlgFromKeyAndCurve(privKeyJWK.KeyType(), jwa.EllipticCurveAlgorithm(crv))
	if err != nil {
		return nil, errors.Wrap(err, "could not get verification alg from jwk")
	}
	return &JSONWebKeySigner{
		SignatureAlgorithm: alg,
		Key:                privKeyJWK,
	}, nil
}

type JSONWebKeyVerifier struct {
	jwa.SignatureAlgorithm
	jwk.Key
}

func (v JSONWebKeyVerifier) KeyID() string {
	return v.Key.KeyID()
}

func (v JSONWebKeyVerifier) KeyType() string {
	return string(v.Key.KeyType())
}

func (v JSONWebKeyVerifier) Verify(message, signature []byte) error {
	_, err := jws.Verify(signature, jwa.EdDSA, v.Key, jws.VerifyOption(jws.WithDetachedPayload(message)))
	return err
}

func NewJSONWebKeyVerifier(key PublicKeyJWK) (*JSONWebKeyVerifier, error) {
	if key.KID == "" {
		return nil, errors.New("key must have an `kid` value")
	}
	pubKeyJWKBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	pubKeyJWK, err := jwk.ParseKey(pubKeyJWKBytes)
	if err != nil {
		return nil, err
	}
	var crv string
	if maybeCrv, b := pubKeyJWK.Get("crv"); b {
		if strCrv, ok := maybeCrv.(string); ok {
			crv = strCrv
		}
		return nil, fmt.Errorf("could not get curve value: %+v", maybeCrv)
	}

	alg, err := AlgFromKeyAndCurve(pubKeyJWK.KeyType(), jwa.EllipticCurveAlgorithm(crv))
	if err != nil {
		return nil, errors.Wrap(err, "could not get verification alg from jwk")
	}
	return &JSONWebKeyVerifier{
		SignatureAlgorithm: alg,
		Key:                pubKeyJWK,
	}, nil
}

func AlgFromKeyAndCurve(kty jwa.KeyType, crv jwa.EllipticCurveAlgorithm) (jwa.SignatureAlgorithm, error) {
	if kty == jwa.RSA {
		return jwa.RS256, nil
	}

	if crv == "" {
		return "", errors.New("crv must be specified for non-RSA key types")
	}

	curve := crv
	if kty == jwa.OKP {
		switch curve {
		case jwa.Ed25519:
			return jwa.EdDSA, nil
		default:
			return "", fmt.Errorf("unsupported OKP signing curve: %s", curve)
		}
	}

	if kty == jwa.EC {
		switch curve {
		case jwa.EllipticCurveAlgorithm(SECP256k1):
			return jwa.ES256K, nil
		case jwa.P256:
			return jwa.PS256, nil
		case jwa.P384:
			return jwa.PS384, nil
		default:
			return "", fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return "", fmt.Errorf("unsupported key type: %s", kty)
}

func crvPtr(crv CRV) *CRV {
	return &crv
}

func encodeToBase64RawURL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
