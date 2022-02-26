package cryptosuite

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"reflect"

	"github.com/pkg/errors"

	"github.com/TBD54566975/did-sdk/util"
)

type JSONWebKey25519 struct {
	key *JSONWebKey2020
}

func (j *JSONWebKey25519) IsEmpty() bool {
	if j == nil {
		return true
	}
	return reflect.DeepEqual(j, JSONWebKey25519{})
}

func (j *JSONWebKey25519) Generate() error {
	_, privKey, err := util.GenerateEd25519Key()
	if err != nil {
		return err
	}
	return j.ToJSONWebKey2020(privKey)
}

func (j *JSONWebKey25519) ToJSONWebKey2020(privKey []byte) error {
	privateKeyJWK, err := PrivateEd25519JSONWebKey2020(privKey)
	if err != nil {
		return err
	}
	privateKey, err := j.ToPrivateKey()
	if err != nil {
		return err
	}

	publicKey := privateKey.(ed25519.PrivateKey).Public()
	pubKeyBytes := publicKey.([]byte)
	publicKeyJWK, err := PublicEd25519JSONWebKey2020(pubKeyBytes)
	if err != nil {
		return err
	}

	j.key = &JSONWebKey2020{
		PrivateKeyJWK: *privateKeyJWK,
		PublicKeyJWK:  *publicKeyJWK,
	}
	return nil
}

func (j *JSONWebKey25519) ToPublicKey() (crypto.PublicKey, error) {
	if j == nil {
		return nil, errors.New("no jwk present")
	}
	pubKey, err := base64.RawURLEncoding.DecodeString(j.key.PublicKeyJWK.X)
	if err != nil {
		return nil, errors.Wrap(err, "could not decode ed25519 public key value from JWK")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key size<%d> is not equal to required ed25519 public key size: %d", len(pubKey), ed25519.PublicKeySize)
	}
	return pubKey, nil
}

func (j *JSONWebKey25519) ToPrivateKey() (crypto.PrivateKey, error) {
	if j == nil {
		return nil, errors.New("no jwk present")
	}
	decodedD, err := base64.RawURLEncoding.DecodeString(j.key.PrivateKeyJWK.D)
	if err != nil {
		return nil, err
	}
	decodedX, err := base64.RawURLEncoding.DecodeString(j.key.PrivateKeyJWK.X)
	if err != nil {
		return nil, err
	}
	privKey := append(decodedD, decodedX...)
	return privKey, nil
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

func PublicEd25519JSONWebKey2020(pubKey []byte) (*PublicKeyJWK, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key size<%d> is not equal to required ed25519 public key size: %d", len(pubKey), ed25519.PublicKeySize)
	}
	x := base64.RawURLEncoding.EncodeToString(pubKey)
	return &PublicKeyJWK{
		KTY: OKP,
		CRV: Ed25519,
		X:   x,
	}, nil
}

func PrivateEd25519JSONWebKey2020(privKey []byte) (*PrivateKeyJWK, error) {
	if len(privKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("key size<%d> is not equal to required ed25519 private key size: %d", len(privKey), ed25519.PrivateKey{})
	}

	privateHalf := privKey[0 : ed25519.PrivateKeySize/2]
	publicHalf := privKey[ed25519.PrivateKeySize/2:]

	x := base64.RawURLEncoding.EncodeToString(publicHalf)
	d := base64.RawURLEncoding.EncodeToString(privateHalf)

	return &PrivateKeyJWK{
		KTY: OKP,
		CRV: Ed25519,
		X:   x,
		D:   d,
	}, nil
}
