package cryptosuite

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strconv"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"filippo.io/edwards25519"
	"github.com/TBD54566975/did-sdk/util"
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
// https://w3c-ccg.github.io/lds-jws2020/#dfn-jsonwebkey2020
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
			return GenerateEd25519JSONWebKey2020()
		case X25519:
			return GenerateX25519JSONWebKey2020()
		default:
			return nil, nil, fmt.Errorf("unsupported OKP curve: %s", curve)
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
			return nil, nil, fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return nil, nil, fmt.Errorf("unsupported key type: %s", kty)
}

func Ed25519JSONWebKey2020(pubKeyBytes []byte) (*PublicKeyJWK, error) {
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key size<%d> is not equal to required ed25519 public key size: %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}
	x := base64.URLEncoding.EncodeToString(pubKeyBytes)
	return &PublicKeyJWK{
		KTY: OKP,
		CRV: Ed25519,
		X:   x,
	}, nil
}

func GenerateEd25519JSONWebKey2020() (ed25519.PrivateKey, *PublicKeyJWK, error) {
	pubKey, privKey, err := util.GenerateEd25519Key()
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK, err := Ed25519JSONWebKey2020(pubKey)
	if err != nil {
		return nil, nil, err
	}
	return privKey, pubKeyJWK, nil
}

func X25519JSONWebKey2020(pubKeyBytes []byte) (*PublicKeyJWK, error) {
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key size<%d> is not equal to required ed25519 public key size: %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}
	point, err := edwards25519.NewGeneratorPoint().SetBytes(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	x25519PubKey := point.BytesMontgomery()
	x := base64.URLEncoding.EncodeToString(x25519PubKey)
	return &PublicKeyJWK{
		KTY: OKP,
		CRV: Ed25519,
		X:   x,
	}, nil
}

func GenerateX25519JSONWebKey2020() (ed25519.PrivateKey, *PublicKeyJWK, error) {
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
	return privKey, pubKeyJWK, nil
}

func SECP256k1JSONWebKey2020(pubKey secp.PublicKey) (*PublicKeyJWK, error) {
	return &PublicKeyJWK{
		KTY: EC,
		CRV: SECP256k1,
		X:   pubKey.X().String(),
		Y:   pubKey.Y().String(),
	}, nil
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

func P256JSONWebKey2020(pubKey ecdsa.PublicKey) (*PublicKeyJWK, error) {
	return &PublicKeyJWK{
		KTY: EC,
		CRV: P256,
		X:   pubKey.X.String(),
		Y:   pubKey.Y.String(),
	}, nil
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

func P384JSONWebKey2020(pubKey ecdsa.PublicKey) (*PublicKeyJWK, error) {
	return &PublicKeyJWK{
		KTY: EC,
		CRV: P384,
		X:   pubKey.X.String(),
		Y:   pubKey.Y.String(),
	}, nil
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

func RSAJSONWebKey2020(pubKey rsa.PublicKey) (*PublicKeyJWK, error) {
	return &PublicKeyJWK{
		KTY: RSA,
		N:   pubKey.N.String(),
		E:   strconv.Itoa(pubKey.E),
	}, nil
}

func GenerateRSAJSONWebKey2020() (*rsa.PrivateKey, *PublicKeyJWK, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSASize)
	if err != nil {
		return nil, nil, err
	}
	pubKeyJWK, err := RSAJSONWebKey2020(privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, pubKeyJWK, nil
}

type JSONWebKey2020Signer struct {
	ID   string
	Type KeyType

	// JWK specific properties
	kty KTY
	crv *CRV

	// TODO(gabe) JWKPrivateKey wrapper
	ed25519PrivateKey *ed25519.PrivateKey
	ecdsaPrivateKey   *ecdsa.PrivateKey
	rsaPrivateKey     *rsa.PrivateKey
}

func NewJSONWebKey2020Signer(id string, kty KTY, crv *CRV, privateKey crypto.PrivateKey) (*JSONWebKey2020Signer, error) {
	signer := JSONWebKey2020Signer{
		ID:   id,
		Type: JsonWebKey2020,
		kty:  kty,
		crv:  crv,
	}

	if kty == RSA {
		rsaPrivateKey, ok := privateKey.(rsa.PrivateKey)
		if !ok {
			return nil, errors.New("provided RSA key not valid")
		}
		signer.rsaPrivateKey = &rsaPrivateKey
		return &signer, nil
	}

	if crv == nil {
		return nil, errors.New("crv must be specified for non-RSA key types")
	}

	curve := *crv
	if kty == OKP {
		switch curve {
		case Ed25519, X25519:
			ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
			if !ok {
				return nil, errors.New("provided ed25519 key not valid")
			}
			signer.ed25519PrivateKey = &ed25519PrivateKey
			return &signer, nil
		default:
			return nil, fmt.Errorf("unsupported OKP curve: %s", curve)
		}
	}

	if kty == EC {
		switch curve {
		case SECP256k1:
			secp256k1PrivateKey, ok := privateKey.(secp.PrivateKey)
			if !ok {
				return nil, errors.New("provided ed25519 key not valid")
			}
			signer.ecdsaPrivateKey = secp256k1PrivateKey.ToECDSA()
			return &signer, nil
		case P256, P384:
			ecdsaPrivateKey, ok := privateKey.(ecdsa.PrivateKey)
			if !ok {
				return nil, errors.New("provided ecdsa key not valid")
			}
			signer.ecdsaPrivateKey = &ecdsaPrivateKey
			return &signer, nil
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}

	return nil, fmt.Errorf("unsupported key type: %s", kty)
}

type JSONWebKey2020Verifier struct {
	Type      KeyType
	publicKey PublicKeyJWK
}

func (j JSONWebKey2020Signer) KeyID() string {
	return j.ID
}

func (j JSONWebKey2020Signer) KeyType() KeyType {
	return j.Type
}

func (j JSONWebKey2020Signer) Sign(tbs []byte) ([]byte, error) {
	if j.ed25519PrivateKey != nil {
		return j.ed25519PrivateKey.Sign(rand.Reader, tbs, nil)
	}
	if j.ecdsaPrivateKey != nil {
		if j.crv == nil {
			return nil, fmt.Errorf("no crv set for ecdsa signer")
		}
		return signECDSA(*j.crv, j.ecdsaPrivateKey, tbs)
	}
	if j.rsaPrivateKey != nil {
		hasher := crypto.SHA256.New()
		hasher.Write(tbs)
		digest := hasher.Sum(nil)
		return j.rsaPrivateKey.Sign(rand.Reader, digest, crypto.SHA256)
	}
	return nil, errors.New("signer contained no keys")
}

// TODO(gabe) consider a separate ecdsa signer
func signECDSA(crv CRV, key *ecdsa.PrivateKey, tbs []byte) ([]byte, error) {
	var r, s *big.Int
	var err error
	var hasher hash.Hash
	reader := rand.Reader
	switch crv {
	case SECP256k1, P256:
		hasher = crypto.SHA256.New()
	case P384:
		hasher = crypto.SHA384.New()
	default:
		return nil, fmt.Errorf("unable to sign, unknown crv<%s> in signer'", crv)
	}
	hasher.Write(tbs)
	digest := hasher.Sum(nil)
	r, s, err = ecdsa.Sign(reader, key, digest)
	bytes := append(r.Bytes(), s.Bytes()...)
	return bytes, err
}

func (j JSONWebKey2020Verifier) KeyID() string {
	return j.publicKey.KID
}

func (j JSONWebKey2020Verifier) KeyType() KeyType {
	return j.Type
}

func (j JSONWebKey2020Verifier) Verify(tbv []byte) error {
	//TODO implement me
	panic("implement me")
}
