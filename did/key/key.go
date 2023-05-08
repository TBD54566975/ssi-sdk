package key

import (
	gocrypto "crypto"
	"fmt"
	"strings"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"

	"github.com/TBD54566975/ssi-sdk/did"

	"github.com/TBD54566975/ssi-sdk/cryptosuite"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"

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

func (DIDKey) Method() did.Method {
	return did.KeyMethod
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
	if !IsSupportedDIDKeyType(kt) {
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
	if !IsSupportedDIDKeyType(kt) {
		return nil, fmt.Errorf("unsupported did:key type: %s", kt)
	}

	// did:key:<multibase encoded, multicodec identified, public key>
	multiCodec, err := did.KeyTypeToMultiCodec(kt)
	if err != nil {
		return nil, fmt.Errorf("could find mutlicodec for key type<%s> for did:key", kt)
	}
	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(did.Base58BTCMultiBase, codec)
	if err != nil {
		return nil, errors.Wrap(err, "could not encode did:key")
	}
	didKey := DIDKey(fmt.Sprintf("%s:%s", KeyPrefix, encoded))
	return &didKey, nil
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
	if encoding != did.Base58BTCMultiBase {
		return nil, "", "", fmt.Errorf("expected %d encoding but found %d", did.Base58BTCMultiBase, encoding)
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
	ldKeyType, err := did.MultiCodecToLDKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "determining LD key type")
	}
	cryptoKeyType, err := did.MultiCodecToKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "determining key type")
	}
	return pubKeyBytes, ldKeyType, cryptoKeyType, nil
}

// Expand turns the DID key into a compliant DID Document
func (d DIDKey) Expand() (*did.Document, error) {
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

	verificationMethod, err := did.ConstructJWKVerificationMethod(id, keyReference, pubKey, keyType, cryptoKeyType)
	if err != nil {
		return nil, errors.Wrap(err, "could not construct verification method")
	}

	verificationMethodSet := []did.VerificationMethodSet{
		[]string{keyReference},
	}

	return &did.Document{
		Context:              did.KnownDIDContext,
		ID:                   id,
		VerificationMethod:   []did.VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		KeyAgreement:         verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
	}, nil
}

func IsSupportedDIDKeyType(kt crypto.KeyType) bool {
	keyTypes := GetSupportedDIDKeyTypes()
	for _, t := range keyTypes {
		if t == kt {
			return true
		}
	}
	return false
}

func GetSupportedDIDKeyTypes() []crypto.KeyType {
	return []crypto.KeyType{crypto.Ed25519, crypto.X25519, crypto.SECP256k1,
		crypto.P256, crypto.P384, crypto.P521, crypto.RSA}
}

func decodeEncodedKey(d string) ([]byte, cryptosuite.LDKeyType, crypto.KeyType, error) {
	encoding, decoded, err := multibase.Decode(d)
	if err != nil {
		return nil, "", "", err
	}

	if encoding != did.Base58BTCMultiBase {
		return nil, "", "", fmt.Errorf("expected %d encoding but found %d", did.Base58BTCMultiBase, encoding)
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
	ldKeyType, err := did.MultiCodecToLDKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "codec to ld key type")
	}

	cryptoKeyType, err := did.MultiCodecToKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "codec to key type")
	}

	return pubKeyBytes, ldKeyType, cryptoKeyType, nil
}

// decode public key with type
func decodePublicKeyWithType(data []byte) ([]byte, cryptosuite.LDKeyType, error) {
	encoding, decoded, err := multibase.Decode(string(data))
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to decode public key")
	}

	if encoding != did.Base58BTCMultiBase {
		err := fmt.Errorf("expected %d encoding but found %d", did.Base58BTCMultiBase, encoding)
		return nil, "", err
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to decode public key from varint")
	}

	pubKeyBytes := decoded[n:]
	multiCodecValue := multicodec.Code(multiCodec)
	switch multiCodecValue {
	case did.Ed25519MultiCodec:
		return pubKeyBytes, cryptosuite.Ed25519VerificationKey2020, nil
	case did.X25519MultiCodec:
		return pubKeyBytes, cryptosuite.X25519KeyAgreementKey2020, nil
	case did.SHA256MultiCodec:
		return pubKeyBytes, cryptosuite.Ed25519VerificationKey2020, nil
	case did.SECP256k1MultiCodec:
		return pubKeyBytes, cryptosuite.ECDSASECP256k1VerificationKey2019, nil
	case did.P256MultiCodec, did.P384MultiCodec, did.P521MultiCodec, did.RSAMultiCodec:
		return pubKeyBytes, cryptosuite.JSONWebKey2020Type, nil
	default:
		return nil, "", fmt.Errorf("unknown multicodec for did:peer: %d", multiCodecValue)
	}
}
