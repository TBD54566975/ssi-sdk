package cryptosuite

import (
	gocrypto "crypto"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/util"
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
	SECP256k1 CRV = "secp256k1"
	P256      CRV = "P-256"
	P384      CRV = "P-384"
)

// JSONWebKey2020 complies with https://w3c-ccg.github.io/lds-jws2020/#json-web-key-2020
type JSONWebKey2020 struct {
	ID                   string    `json:"id,omitempty"`
	Type                 LDKeyType `json:"type,omitempty"`
	Controller           string    `json:"controller,omitempty"`
	crypto.PrivateKeyJWK `json:"privateKeyJwk,omitempty"`
	crypto.PublicKeyJWK  `json:"publicKeyJwk,omitempty"`
}

func (jwk *JSONWebKey2020) IsValid() error {
	return util.NewValidator().Struct(jwk)
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
		case SECP256k1:
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

// JSONWebKey2020FromPrivateKey returns a JsonWebKey2020 value from a given private key, containing both JWK
// public and private key representations of the key.
func JSONWebKey2020FromPrivateKey(key gocrypto.PrivateKey) (*JSONWebKey2020, error) {
	pubKeyJWK, privKeyJWK, err := crypto.PrivateKeyToPrivateKeyJWK(key)
	if err != nil {
		return nil, err
	}
	return &JSONWebKey2020{
		Type:          JsonWebKey2020,
		PrivateKeyJWK: *privKeyJWK,
		PublicKeyJWK:  *pubKeyJWK,
	}, nil
}

// GenerateRSAJSONWebKey2020 returns a JsonWebKey2020 value, containing both public and private keys
// for an RSA-2048 key.
func GenerateRSAJSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateRSA2048Key()
	if err != nil {
		return nil, err
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateEd25519JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for an Ed25519 key.
func GenerateEd25519JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateEd25519Key()
	if err != nil {
		return nil, err
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateX25519JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for an Ed25519 key transformed to a bi-rationally equivalent X25519 key.
func GenerateX25519JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateX25519Key()
	if err != nil {
		return nil, err
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateSECP256k1JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for a secp256k1 key transformed to an ecdsa key.
// We use the secp256k1 implementation from Decred https://github.com/decred/dcrd
// which is utilized in the widely accepted go bitcoin node implementation from the btcsuite project
// https://github.com/btcsuite/btcd/blob/master/btcec/btcec.go#L23
func GenerateSECP256k1JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateSECP256k1Key()
	if err != nil {
		logrus.WithError(err).Error("could not generate secp256k1 key")
		return nil, err
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateP256JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for a P-256 ECDSA key.
func GenerateP256JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateP256Key()
	if err != nil {
		logrus.WithError(err).Error("could not generate p-256 key")
		return nil, err
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// GenerateP384JSONWebKey2020 returns a JsonWebKey2020 value, containing both public and
// private keys for a P-384 ECDSA key.
func GenerateP384JSONWebKey2020() (*JSONWebKey2020, error) {
	_, privKey, err := crypto.GenerateP384Key()
	if err != nil {
		logrus.WithError(err).Error("could not generate p-384 key")
		return nil, err
	}
	return JSONWebKey2020FromPrivateKey(privKey)
}

// JSONWebKeySigner constructs a signer for a JSONWebKey2020 object.
// Given a signature algorithm (e.g. ES256, PS384) and a JSON Web Key (private key), the signer is able to accept
// a message and provide a valid JSON Web Signature (JWS) value as a result.
type JSONWebKeySigner struct {
	crypto.JWTSigner
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

func NewJSONWebKeySigner(kid string, key crypto.PrivateKeyJWK, purpose ProofPurpose) (*JSONWebKeySigner, error) {
	signer, err := crypto.NewJWTSigner(kid, key)
	if err != nil {
		return nil, err
	}
	return &JSONWebKeySigner{
		JWTSigner: *signer,
		purpose:   purpose,
	}, nil
}

// JSONWebKeyVerifier constructs a verifier for a JSONWebKey2020 object.
// Given a signature algorithm (e.g. ES256, PS384) and a JSON Web Key (pub key), the verifier is able to accept
// a message and signature, and provide a result to whether the signature is valid.
type JSONWebKeyVerifier struct {
	crypto.JWTVerifier
}

// Verify attempts to verify a `signature` against a given `message`, returning nil if the verification is successful
// and an error should it fail.
func (v *JSONWebKeyVerifier) Verify(message, signature []byte) error {
	_, err := jws.Verify(signature, jwa.SignatureAlgorithm(v.Algorithm()), v.Key, jws.WithDetachedPayload(message))
	if err != nil {
		logrus.WithError(err).Error("could not verify JWK")
	}
	return err
}

func (v *JSONWebKeyVerifier) GetKeyID() string {
	return v.Key.KeyID()
}

func (v *JSONWebKeyVerifier) GetKeyType() string {
	return string(v.Key.KeyType())
}

func NewJSONWebKeyVerifier(kid string, key crypto.PublicKeyJWK) (*JSONWebKeyVerifier, error) {
	verifier, err := crypto.NewJWTVerifier(kid, key)
	if err != nil {
		return nil, err
	}
	return &JSONWebKeyVerifier{
		JWTVerifier: *verifier,
	}, nil
}
