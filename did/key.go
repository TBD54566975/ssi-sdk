package did

import (
	"context"
	gocrypto "crypto"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
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
	// KeyPrefix did:key prefix
	KeyPrefix = "did:key"
)

func (d DIDKey) IsValid() bool {
	_, err := d.Expand()
	return err == nil
}

func (d DIDKey) String() string {
	return string(d)
}

// Suffix returns the value without the `did:key` prefix
func (d DIDKey) Suffix() (string, error) {
	split := strings.Split(string(d), KeyPrefix+":")
	if len(split) != 2 {
		return "", fmt.Errorf("invalid did:key: %s", d)
	}
	return split[1], nil
}

func (DIDKey) Method() Method {
	return KeyMethod
}

// GenerateDIDKey takes in a key type value that this library supports and constructs a conformant did:key identifier.
// The function returns the associated private key value cast to the generic golang crypto.PrivateKey interface.
// To use the private key, it is recommended to re-cast to the associated type. For example, called with the input
// for a secp256k1 key:
// privKey, didKey, err := GenerateDIDKey(SECP256k1)
// if err != nil { ... }
// // where secp is an import alias to the secp256k1 library we use "github.com/decred/dcrd/dcrec/secp256k1/v4"
// secpPrivKey, ok := privKey.(secp.PrivateKey)
// if !ok { ... }
func GenerateDIDKey(kt crypto.KeyType) (gocrypto.PrivateKey, *DIDKey, error) {
	if !isSupportedKeyType(kt) {
		return nil, nil, fmt.Errorf("unsupported did:key type: %s", kt)
	}

	pubKey, privKey, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not generate key for did:key")
	}

	pubKeyBytes, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not convert public key to byte")
	}

	didKey, err := CreateDIDKey(kt, pubKeyBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not create DID key")
	}
	return privKey, didKey, err
}

// CreateDIDKey constructs a did:key from a specific key type and its corresponding public key
// This method does not attempt to validate that the provided public key is of the specified key type.
// A safer method is `GenerateDIDKey` which handles key generation based on the provided key type.
func CreateDIDKey(kt crypto.KeyType, publicKey []byte) (*DIDKey, error) {
	if !isSupportedKeyType(kt) {
		return nil, fmt.Errorf("unsupported did:key type: %s", kt)
	}

	// did:key:<multibase encoded, multicodec identified, public key>
	multiCodec, err := keyTypeToMultiCodec(kt)
	if err != nil {
		return nil, fmt.Errorf("could find mutlicodec for key type<%s> for did:key", kt)
	}
	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(Base58BTCMultiBase, codec)
	if err != nil {
		return nil, errors.Wrap(err, "could not encode did:key")
	}
	did := DIDKey(fmt.Sprintf("%s:%s", KeyPrefix, encoded))
	return &did, nil
}

// Decode takes a did:key and returns the underlying public key value as bytes, the LD key type, and a possible error
func (d DIDKey) Decode() ([]byte, cryptosuite.LDKeyType, crypto.KeyType, error) {
	parsed, err := d.Suffix()
	if err != nil {
		return nil, "", "", errors.Wrap(err, "could not parse did:key")
	}
	if parsed == "" {
		return nil, "", "", fmt.Errorf("could not decode did:key value: %s", string(d))
	}

	encoding, decoded, err := multibase.Decode(parsed)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "could not decode did:key")
	}
	if encoding != Base58BTCMultiBase {
		return nil, "", "", fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", "", err
	}
	if n != 2 {
		return nil, "", "", errors.New("error parsing did:key varint")
	}

	pubKeyBytes := decoded[n:]
	multiCodecValue := multicodec.Code(multiCodec)
	ldKeyType, err := codecToLDKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "determining LD key type")
	}
	cryptoKeyType, err := codecToKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "determining key type")
	}
	return pubKeyBytes, ldKeyType, cryptoKeyType, nil
}

func codecToLDKeyType(codec multicodec.Code) (cryptosuite.LDKeyType, error) {
	switch codec {
	case Ed25519MultiCodec:
		return cryptosuite.Ed25519VerificationKey2018, nil
	case X25519MultiCodec:
		return cryptosuite.X25519KeyAgreementKey2019, nil
	case SECP256k1MultiCodec:
		return cryptosuite.ECDSASECP256k1VerificationKey2019, nil
	case P256MultiCodec, P384MultiCodec, P521MultiCodec, RSAMultiCodec:
		return cryptosuite.JSONWebKey2020Type, nil
	default:
		return "", fmt.Errorf("unknown multicodec for did:key: %d", codec)
	}
}

// Expand turns the DID key into a compliant DID Document
func (d DIDKey) Expand() (*Document, error) {
	parsed, err := d.Suffix()
	if err != nil {
		return nil, errors.Wrap(err, "could not parse did:key")
	}

	keyReference := "#" + parsed
	id := string(d)

	pubKey, keyType, cryptoKeyType, err := d.Decode()
	if err != nil {
		return nil, errors.Wrap(err, "could not decode did:key")
	}

	verificationMethod, err := constructVerificationMethod(id, keyReference, pubKey, keyType, cryptoKeyType)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct verification method")
	}

	verificationMethodSet := []VerificationMethodSet{
		[]string{keyReference},
	}

	return &Document{
		Context:              KnownDIDContext,
		ID:                   id,
		VerificationMethod:   []VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		KeyAgreement:         verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
	}, nil
}

func codecToKeyType(codec multicodec.Code) (crypto.KeyType, error) {
	var kt crypto.KeyType
	switch codec {
	case Ed25519MultiCodec:
		kt = crypto.Ed25519
	case X25519MultiCodec:
		kt = crypto.X25519
	case SECP256k1MultiCodec:
		kt = crypto.SECP256k1
	case P256MultiCodec:
		kt = crypto.P256
	case P384MultiCodec:
		kt = crypto.P384
	case P521MultiCodec:
		kt = crypto.P521
	case RSAMultiCodec:
		kt = crypto.RSA
	default:
		return kt, errors.Errorf("codec conversion not found for %d", codec)
	}
	return kt, nil
}

func constructVerificationMethod(id, keyReference string, pubKey []byte, keyType cryptosuite.LDKeyType, cryptoKeyType crypto.KeyType) (*VerificationMethod, error) {
	if keyType != cryptosuite.JSONWebKey2020Type {
		return &VerificationMethod{
			ID:              keyReference,
			Type:            keyType,
			Controller:      id,
			PublicKeyBase58: base58.Encode(pubKey),
		}, nil
	}

	cryptoPubKey, err := crypto.BytesToPubKey(pubKey, cryptoKeyType)
	if err != nil {
		return nil, errors.Wrap(err, "converting bytes to public key")
	}

	standardJWK, err := jwk.FromRaw(cryptoPubKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not expand key of type JsonWebKey2020")
	}

	pubKeyJWK, err := crypto.JWKToPublicKeyJWK(standardJWK)
	if err != nil {
		return nil, errors.Wrap(err, "could convert did:key to PublicKeyJWK")
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
	return []crypto.KeyType{crypto.Ed25519, crypto.X25519, crypto.SECP256k1, crypto.P256, crypto.P384, crypto.P521, crypto.RSA}
}

type KeyResolver struct{}

var _ Resolver = (*KeyResolver)(nil)

func (KeyResolver) Resolve(_ context.Context, did string, _ ...ResolutionOption) (*ResolutionResult, error) {
	if !strings.HasPrefix(did, KeyPrefix) {
		return nil, fmt.Errorf("not a did:key DID: %s", did)
	}
	didKey := DIDKey(did)
	doc, err := didKey.Expand()
	if err != nil {
		return nil, errors.Wrapf(err, "could not expand did:key DID: %s", did)
	}
	return &ResolutionResult{Document: *doc}, nil
}

func (KeyResolver) Methods() []Method {
	return []Method{KeyMethod}
}
