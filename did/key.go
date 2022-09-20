package did

import (
	gocrypto "crypto"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/mr-tron/base58"

	"github.com/TBD54566975/ssi-sdk/cryptosuite"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

type (
	DIDKey string
)

const (
	// DIDKeyPrefix did:key prefix
	DIDKeyPrefix = "did:key"
)

func (d DIDKey) IsValid() bool {
	_, err := d.Expand()
	return err == nil
}

func (d DIDKey) ToString() string {
	return string(d)
}

// Parse returns the value without the `did:key` prefix
func (d DIDKey) Parse() (string, error) {
	split := strings.Split(string(d), DIDKeyPrefix+":")
	if len(split) != 2 {
		return "", fmt.Errorf("invalid did:key: %s", d)
	}
	return split[1], nil
}

// GenerateDIDKey takes in a key type value that this library supports and constructs a conformant did:key identifier.
// The function returns the associated private key value cast to the generic golang crypto.PrivateKey interface.
// To use the private key, it is recommended to re-cast to the associated type. For example, called with the input
// for a secp256k1 key:
// privKey, didKey, err := GenerateDIDKey(Secp256k1)
// if err != nil { ... }
// // where secp is an import alias to the secp256k1 library we use "github.com/decred/dcrd/dcrec/secp256k1/v4"
// secpPrivKey, ok := privKey.(secp.PrivateKey)
// if !ok { ... }
func GenerateDIDKey(kt crypto.KeyType) (gocrypto.PrivateKey, *DIDKey, error) {
	if !isSupportedKeyType(kt) {
		err := fmt.Errorf("unsupported did:key type: %s", kt)
		logrus.WithError(err).Error()
		return nil, nil, err
	}

	pubKey, privKey, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		errMsg := "could not generate key for did:key"
		logrus.WithError(err).Error(errMsg)
		return nil, nil, errors.Wrap(err, errMsg)
	}

	pubKeyBytes, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		logrus.WithError(err).Error("could not convert public key to byte")
		return nil, nil, err
	}

	didKey, err := CreateDIDKey(kt, pubKeyBytes)
	if err != nil {
		logrus.WithError(err).Error("could not create DID key")
		return nil, nil, err
	}
	return privKey, didKey, err
}

// CreateDIDKey constructs a did:key from a specific key type and its corresponding public key
// This method does not attempt to validate that the provided public key is of the specified key type.
// A safer method is `GenerateDIDKey` which handles key generation based on the provided key type.
func CreateDIDKey(kt crypto.KeyType, publicKey []byte) (*DIDKey, error) {
	if !isSupportedKeyType(kt) {
		err := fmt.Errorf("unsupported did:key type: %s", kt)
		logrus.WithError(err).Error()
		return nil, err
	}

	// did:key:<multibase encoded, multicodec identified, public key>
	multiCodec, err := keyTypeToMultiCodec(kt)
	if err != nil {
		logrus.WithError(err).Errorf("could find mutlicodec for key type<%s> for did:key", kt)
		return nil, err
	}
	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(Base58BTCMultiBase, codec)
	if err != nil {
		logrus.WithError(err).Error("could not encode did:key")
		return nil, err
	}
	did := DIDKey(fmt.Sprintf("%s:%s", DIDKeyPrefix, encoded))
	return &did, nil
}

// Decode takes a did:key and returns the underlying public key value as bytes, the LD key type, and a possible error
func (d DIDKey) Decode() ([]byte, cryptosuite.LDKeyType, error) {
	parsed, err := d.Parse()
	if err != nil {
		return nil, "", errors.Wrap(err, "could not parse did:key")
	}
	if parsed == "" {
		err := fmt.Errorf("could not decode did:key value: %s", string(d))
		logrus.WithError(err).Error()
		return nil, "", err
	}

	encoding, decoded, err := multibase.Decode(parsed)
	if err != nil {
		logrus.WithError(err).Error("could not decode did:key")
		return nil, "", err
	}
	if encoding != Base58BTCMultiBase {
		err := fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
		logrus.WithError(err).Error()
		return nil, "", err
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", err
	}
	if n != 2 {
		errMsg := "Error parsing did:key varint"
		logrus.Error(errMsg)
		return nil, "", errors.New(errMsg)
	}

	pubKeyBytes := decoded[n:]
	multiCodecValue := multicodec.Code(multiCodec)
	switch multiCodecValue {
	case Ed25519MultiCodec:
		return pubKeyBytes, Ed25519VerificationKey2018, nil
	case X25519MultiCodec:
		return pubKeyBytes, X25519KeyAgreementKey2019, nil
	case Secp256k1MultiCodec:
		return pubKeyBytes, EcdsaSecp256k1VerificationKey2019, nil
	case P256MultiCodec, P384MultiCodec, P521MultiCodec, RSAMultiCodec:
		return pubKeyBytes, cryptosuite.JsonWebKey2020, nil
	default:
		err := fmt.Errorf("unknown multicodec for did:key: %d", multiCodecValue)
		logrus.WithError(err).Error()
		return nil, "", err
	}
}

// Expand turns the DID key into a compliant DID Document
func (d DIDKey) Expand() (*DIDDocument, error) {
	parsed, err := d.Parse()
	if err != nil {
		return nil, errors.Wrap(err, "could not parse did:key")
	}

	keyReference := "#" + parsed
	id := string(d)

	pubKey, keyType, err := d.Decode()
	if err != nil {
		logrus.WithError(err).Error("could not decode did:key")
		return nil, err
	}

	verificationMethod, err := constructVerificationMethod(id, keyReference, pubKey, keyType)
	if err != nil {
		logrus.WithError(err).Error("could not construct verification method")
		return nil, err
	}

	verificationMethodSet := []VerificationMethodSet{
		[]string{keyReference},
	}

	return &DIDDocument{
		Context:              KnownDIDContext,
		ID:                   id,
		VerificationMethod:   []VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		KeyAgreement:         verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
	}, nil
}

func constructVerificationMethod(id, keyReference string, pubKey []byte, keyType cryptosuite.LDKeyType) (*VerificationMethod, error) {
	if keyType != cryptosuite.JsonWebKey2020 {
		return &VerificationMethod{
			ID:              keyReference,
			Type:            keyType,
			Controller:      id,
			PublicKeyBase58: base58.Encode(pubKey),
		}, nil
	}

	standardJWK, err := jwk.New(pubKey)
	if err != nil {
		errMsg := "could not expand key of type JsonWebKey2020"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	pubKeyJWK, err := crypto.JWKToPublicKeyJWK(standardJWK)
	if err != nil {
		errMsg := "could convert did:key to PublicKeyJWK"
		logrus.WithError(err).Error(errMsg)
		return nil, errors.Wrap(err, errMsg)
	}

	return &VerificationMethod{
		ID:           keyReference,
		Type:         keyType,
		Controller:   id,
		PublicKeyJWK: pubKeyJWK,
	}, nil
}

func isSupportedKeyType(kt crypto.KeyType) bool {
	keyTypes := GetSupportedDIDKeyTypes()
	for _, t := range keyTypes {
		if t == kt {
			return true
		}
	}
	return false
}

func GetSupportedDIDKeyTypes() []crypto.KeyType {
	return []crypto.KeyType{crypto.Ed25519, crypto.X25519, crypto.Secp256k1, crypto.P256, crypto.P384, crypto.P521, crypto.RSA}
}
