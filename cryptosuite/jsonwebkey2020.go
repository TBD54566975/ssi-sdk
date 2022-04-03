//go:build jwx_es256k

package cryptosuite

import (
	"encoding/base64"
	"fmt"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

type (
	KTY       string
	CRV       string
	ALG       string
	LDKeyType string
)

const (
	JsonWebKey2020 LDKeyType = "JsonWebKey2020"

	// Supported key types

	OKP KTY = "OKP"
	EC  KTY = "EC"
	RSA KTY = "RSA"

	// Supported curves

	Ed25519   CRV = "Ed25519"
	X25519    CRV = "X25519"
	Secp256k1 CRV = "secp256k1"
	P256      CRV = "P-256"
	P384      CRV = "P-384"
)

// JSONWebKey2020 complies with https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020
type JSONWebKey2020 struct {
	ID            string    `json:"id,omitempty"`
	Type          LDKeyType `json:"type,omitempty"`
	Controller    string    `json:"controller,omitempty"`
	PrivateKeyJWK `json:"privateKeyJwk,omitempty"`
	PublicKeyJWK  `json:"publicKeyJwk,omitempty"`
}

func (jwk *JSONWebKey2020) IsValid() error {
	return util.NewValidator().Struct(jwk)
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

// GenerateJSONWebKey2020 The JSONWebKey2020 type specifies a number of key type and curve pairs to enable JOSE conformance
// these pairs are supported in this library and generated via the function below
// https://w3c-ccg.github.io/lds-jws2020/#dfn-jsonwebkey2020
func GenerateJSONWebKey2020(kty KTY, crv CRV) (*JSONWebKey2020, error) {
	if kty == RSA {
		if crv != "" {
			return nil, fmt.Errorf("RSA key type cannot have curve specified: %s", crv)
		}
		return GenerateRSAJSONWebKey2020()
	}
	if crv == "" {
		return nil, errors.New("crv must be specified for non-RSA key types")
	}
	if kty == OKP {
		switch crv {
		case Ed25519:
			return GenerateEd25519JSONWebKey2020()
		case X25519:
			return GenerateX25519JSONWebKey2020()
		default:
			return nil, fmt.Errorf("unsupported OKP curve: %s", crv)
		}

	}
	if kty == EC {
		switch crv {
		case Secp256k1:
			return GenerateSECP256k1JSONWebKey2020()
		case P256:
			return GenerateP256JSONWebKey2020()
		case P384:
			return GenerateP384JSONWebKey2020()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", crv)
		}
	}
	return nil, fmt.Errorf("unsupported key type: %s", kty)
}

// GenerateRSAJSONWebKey2020 returns a JsonWebKey2020 value, containing both public and private keys
// for an RSA-2048 key.
func GenerateRSAJSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateRSA2048Key()
	if err != nil {
		return nil, err
	}
	rsaJWK := jwk.NewRSAPrivateKey()
	if err := rsaJWK.FromRaw(&privKey); err != nil {
		return nil, errors.Wrap(err, "failed to generate rsa jwk")
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

// GenerateEd25519JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for an Ed25519 key.
func GenerateEd25519JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateEd25519Key()
	if err != nil {
		return nil, err
	}
	ed25519JWK := jwk.NewOKPPrivateKey()
	if err := ed25519JWK.FromRaw(privKey); err != nil {
		return nil, errors.Wrap(err, "failed to generate ed25519 jwk")
	}

	kty := ed25519JWK.KeyType().String()
	crv := ed25519JWK.Crv().String()
	x := encodeToBase64RawURL(ed25519JWK.X())
	return &JSONWebKey2020{
		Type: JsonWebKey2020,
		PrivateKeyJWK: PrivateKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
			D:   encodeToBase64RawURL(ed25519JWK.D()),
		},
		PublicKeyJWK: PublicKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
		},
	}, nil
}

// GenerateX25519JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for an Ed25519 key transformed to a bi-rationally equivalent X25519 key.
func GenerateX25519JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateX25519Key()
	if err != nil {
		return nil, err
	}
	x25519JWK := jwk.NewOKPPrivateKey()
	if err := x25519JWK.FromRaw(privKey); err != nil {
		return nil, errors.Wrap(err, "failed to generate x25519 jwk")
	}

	kty := x25519JWK.KeyType().String()
	crv := x25519JWK.Crv().String()
	x := encodeToBase64RawURL(x25519JWK.X())
	return &JSONWebKey2020{
		Type: JsonWebKey2020,
		PrivateKeyJWK: PrivateKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
			D:   encodeToBase64RawURL(x25519JWK.D()),
		},
		PublicKeyJWK: PublicKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
		},
	}, nil
}

// GenerateSECP256k1JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for a secp256k1 key transformed to an ecdsa key.
// We use the secp256k1 implementation from Decred https://github.com/decred/dcrd
// which is utilized in the widely accepted go bitcoin node implementation from the btcsuite project
// https://github.com/btcsuite/btcd/blob/master/btcec/btcec.go#L23
func GenerateSECP256k1JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateSecp256k1Key()
	if err != nil {
		return nil, err
	}
	ecdsaPrivKey := privKey.ToECDSA()
	secp256k1JWK := jwk.NewECDSAPrivateKey()
	if err := secp256k1JWK.FromRaw(ecdsaPrivKey); err != nil {
		return nil, errors.Wrap(err, "failed to generate secp256k1 jwk")
	}
	kty := secp256k1JWK.KeyType().String()
	crv := secp256k1JWK.Crv().String()
	x := encodeToBase64RawURL(secp256k1JWK.X())
	y := encodeToBase64RawURL(secp256k1JWK.Y())
	return &JSONWebKey2020{
		Type: JsonWebKey2020,
		PrivateKeyJWK: PrivateKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
			Y:   y,
			D:   encodeToBase64RawURL(secp256k1JWK.D()),
		},
		PublicKeyJWK: PublicKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
			Y:   y,
		},
	}, nil
}

// GenerateP256JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for a P-256 ECDSA key.
func GenerateP256JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateP256Key()
	if err != nil {
		return nil, err
	}
	p256JWK := jwk.NewECDSAPrivateKey()
	if err := p256JWK.FromRaw(&privKey); err != nil {
		return nil, errors.Wrap(err, "failed to generate p-256 jwk")
	}
	kty := p256JWK.KeyType().String()
	crv := p256JWK.Crv().String()
	x := encodeToBase64RawURL(p256JWK.X())
	y := encodeToBase64RawURL(p256JWK.Y())
	return &JSONWebKey2020{
		Type: JsonWebKey2020,
		PrivateKeyJWK: PrivateKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
			Y:   y,
			D:   encodeToBase64RawURL(p256JWK.D()),
		},
		PublicKeyJWK: PublicKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
			Y:   y,
		},
	}, nil
}

// GenerateP384JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for a P-384 ECDSA key.
func GenerateP384JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateP384Key()
	if err != nil {
		return nil, err
	}
	p384JWK := jwk.NewECDSAPrivateKey()
	if err := p384JWK.FromRaw(&privKey); err != nil {
		return nil, errors.Wrap(err, "failed to generate p-384 jwk")
	}
	kty := p384JWK.KeyType().String()
	crv := p384JWK.Crv().String()
	x := encodeToBase64RawURL(p384JWK.X())
	y := encodeToBase64RawURL(p384JWK.Y())
	return &JSONWebKey2020{
		Type: JsonWebKey2020,
		PrivateKeyJWK: PrivateKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
			Y:   y,
			D:   encodeToBase64RawURL(p384JWK.D()),
		},
		PublicKeyJWK: PublicKeyJWK{
			KTY: kty,
			CRV: crv,
			X:   x,
			Y:   y,
		},
	}, nil
}

type JSONWebKeySigner struct {
	jwa.SignatureAlgorithm
	jwk.Key
	purpose ProofPurpose
	format  PayloadFormat
}

// Sign returns a byte array signature value for a message `tbs`
func (s *JSONWebKeySigner) Sign(tbs []byte) ([]byte, error) {
	b64 := "b64"
	headers := jws.NewHeaders()
	if err := headers.Set(b64, false); err != nil {
		return nil, err
	}
	if err := headers.Set(jws.CriticalKey, []string{b64}); err != nil {
		return nil, err
	}
	signOptions := []jws.SignOption{jws.WithHeaders(headers), jws.WithDetachedPayload(tbs)}
	return jws.Sign(nil, s.SignatureAlgorithm, s.Key, signOptions...)
}

func (s *JSONWebKeySigner) GetKeyID() string {
	return s.Key.KeyID()
}

func (s *JSONWebKeySigner) GetKeyType() string {
	return string(s.Key.KeyType())
}

func (s *JSONWebKeySigner) GetSignatureType() SignatureType {
	return JSONWebSignature2020
}

func (s *JSONWebKeySigner) GetSigningAlgorithm() string {
	return s.Algorithm()
}

func (s *JSONWebKeySigner) SetProofPurpose(purpose ProofPurpose) {
	s.purpose = purpose
}

func (s *JSONWebKeySigner) GetProofPurpose() ProofPurpose {
	return s.purpose
}

func (s *JSONWebKeySigner) SetPayloadFormat(format PayloadFormat) {
	s.format = format
}

func (s *JSONWebKeySigner) GetPayloadFormat() PayloadFormat {
	return s.format
}

func NewJSONWebKeySigner(kid string, key PrivateKeyJWK, purpose ProofPurpose) (*JSONWebKeySigner, error) {
	privKeyJWKBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	privKeyJWK, err := jwk.ParseKey(privKeyJWKBytes)
	if err != nil {
		return nil, err
	}
	crv, err := getCrvFromJWK(privKeyJWK)
	if err != nil {
		return nil, err
	}
	alg, err := AlgFromKeyAndCurve(privKeyJWK.KeyType(), jwa.EllipticCurveAlgorithm(crv))
	if err != nil {
		return nil, errors.Wrap(err, "could not get verification alg from jwk")
	}
	if err := privKeyJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("could not set kid with provided value: %s", kid)
	}
	if err := privKeyJWK.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf("could not set alg with value: %s", alg)
	}
	return &JSONWebKeySigner{
		SignatureAlgorithm: alg,
		Key:                privKeyJWK,
		purpose:            purpose,
	}, nil
}

type JSONWebKeyVerifier struct {
	jwa.SignatureAlgorithm
	jwk.Key
}

// Verify attempts to verify a `signature` against a given `message`, returning nil if the verification is successful
// and an error should it fail.
func (v *JSONWebKeyVerifier) Verify(message, signature []byte) error {
	_, err := jws.Verify(signature, v.SignatureAlgorithm, v.Key, jws.VerifyOption(jws.WithDetachedPayload(message)))
	return err
}

func (v *JSONWebKeyVerifier) GetKeyID() string {
	return v.Key.KeyID()
}

func (v *JSONWebKeyVerifier) GetKeyType() string {
	return string(v.Key.KeyType())
}

func NewJSONWebKeyVerifier(kid string, key PublicKeyJWK) (*JSONWebKeyVerifier, error) {
	pubKeyJWKBytes, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}
	pubKeyJWK, err := jwk.ParseKey(pubKeyJWKBytes)
	if err != nil {
		return nil, err
	}
	crv, err := getCrvFromJWK(pubKeyJWK)
	if err != nil {
		return nil, err
	}
	alg, err := AlgFromKeyAndCurve(pubKeyJWK.KeyType(), jwa.EllipticCurveAlgorithm(crv))
	if err != nil {
		return nil, errors.Wrap(err, "could not get verification alg from jwk")
	}
	if err := pubKeyJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("could not set kid with provided value: %s", kid)
	}
	if err := pubKeyJWK.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf("could not set alg with value: %s", alg)
	}
	return &JSONWebKeyVerifier{
		SignatureAlgorithm: alg,
		Key:                pubKeyJWK,
	}, nil
}

// AlgFromKeyAndCurve returns the supported JSON Web Algorithm for signing for a given key type and curve pair
// The curve parameter is optional (e.g. "") as in the case of RSA.
func AlgFromKeyAndCurve(kty jwa.KeyType, crv jwa.EllipticCurveAlgorithm) (jwa.SignatureAlgorithm, error) {
	if kty == jwa.RSA {
		return jwa.PS256, nil
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
		case jwa.EllipticCurveAlgorithm(Secp256k1):
			return jwa.ES256K, nil
		case jwa.P256:
			return jwa.ES256, nil
		case jwa.P384:
			return jwa.ES384, nil
		default:
			return "", fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return "", fmt.Errorf("unsupported key type: %s", kty)
}

func encodeToBase64RawURL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func getCrvFromJWK(jwk jwk.Key) (string, error) {
	maybeCrv, hasCrv := jwk.Get("crv")
	if hasCrv {
		crv, crvStr := maybeCrv.(jwa.EllipticCurveAlgorithm)
		if !crvStr {
			return "", fmt.Errorf("could not get crv value: %+v", maybeCrv)
		}
		return crv.String(), nil
	}
	return "", nil
}
