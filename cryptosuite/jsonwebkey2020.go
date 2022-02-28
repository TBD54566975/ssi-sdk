//go:build jwx_es256k

package cryptosuite

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/x25519"

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

	// Known key sizes

	RSAKeySize int = 2048
)

// JSONWebKey2020 complies with https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020
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

// GenerateJSONWebKey2020 The JSONWebKey2020 type specifies a number of key type and curve pairs to enable JOSE conformance
// these pairs are supported in this library and generated via the function below
// https://w3c-ccg.github.io/lds-jws2020/#dfn-jsonwebkey2020
func GenerateJSONWebKey2020(kty KTY, crv *CRV) (*JSONWebKey2020, error) {
	if kty == RSA {
		if crv != nil {
			return nil, fmt.Errorf("RSA key type cannot have curve specified: %s", *crv)
		}
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

func GenerateEd25519JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := util.GenerateEd25519Key()
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

func GenerateX25519JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := x25519.GenerateKey(rand.Reader)
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

func GenerateSECP256k1JSONWebKey2020() (*JSONWebKey2020, error) {
	// We use the secp256k1 implementation from Decred https://github.com/decred/dcrd
	// which is utilized in the widely accepted go bitcoin node implementation from the btcsuite project
	// https://github.com/btcsuite/btcd/blob/master/btcec/btcec.go#L23
	privKey, err := secp.GeneratePrivateKey()
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

func GenerateP256JSONWebKey2020() (*JSONWebKey2020, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	p256JWK := jwk.NewECDSAPrivateKey()
	if err := p256JWK.FromRaw(privKey); err != nil {
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

func GenerateP384JSONWebKey2020() (*JSONWebKey2020, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	p384JWK := jwk.NewECDSAPrivateKey()
	if err := p384JWK.FromRaw(privKey); err != nil {
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
}

func (s JSONWebKeySigner) SignatureType() SignatureType {
	return JSONWebSignature2020
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
	if err := headers.Set(jws.CriticalKey, []string{"b64"}); err != nil {
		return nil, err
	}
	signOptions := []jws.SignOption{jws.WithHeaders(headers), jws.WithDetachedPayload(tbs)}
	return jws.Sign(nil, s.SignatureAlgorithm, s.Key, signOptions...)
}

func NewJSONWebKeySigner(key PrivateKeyJWK) (*JSONWebKeySigner, error) {
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
	_, err := jws.Verify(signature, v.SignatureAlgorithm, v.Key, jws.VerifyOption(jws.WithDetachedPayload(message)))
	return err
}

func NewJSONWebKeyVerifier(key PublicKeyJWK) (*JSONWebKeyVerifier, error) {
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
			return jwa.ES256, nil
		case jwa.P384:
			return jwa.ES384, nil
		default:
			return "", fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return "", fmt.Errorf("unsupported key type: %s", kty)
}

func crvPtr(crv CRV) *CRV {
	if crv == "" {
		return nil
	}
	return &crv
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
