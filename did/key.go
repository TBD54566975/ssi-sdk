package did

import (
	gocrypto "crypto"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/mr-tron/base58"

	"github.com/TBD54566975/did-sdk/cryptosuite"

	"github.com/pkg/errors"

	"github.com/TBD54566975/did-sdk/crypto"

	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
)

type DIDKey string

const (
	// Base58BTCMultiBase Base58BTC https://github.com/multiformats/go-multibase/blob/master/multibase.go
	Base58BTCMultiBase = multibase.Base58BTC

	// Multicodec reference https://github.com/multiformats/multicodec/blob/master/table.csv

	Ed25519MultiCodec   = multicodec.Ed25519Pub
	X25519MultiCodec    = multicodec.X25519Pub
	Secp256k1MultiCodec = multicodec.Secp256k1Pub
	P256MultiCodec      = multicodec.P256Pub
	P384MultiCodec      = multicodec.P384Pub
	P521MultiCodec      = multicodec.P521Pub
	RSAMultiCodec       = multicodec.RsaPub

	// DIDKeyPrefix did:key prefix
	DIDKeyPrefix = "did:key"

	// DID Key Types

	X25519KeyAgreementKey2019         cryptosuite.LDKeyType = "X25519KeyAgreementKey2019"
	Ed25519VerificationKey2018        cryptosuite.LDKeyType = "Ed25519VerificationKey2018"
	EcdsaSecp256k1VerificationKey2019 cryptosuite.LDKeyType = "EcdsaSecp256k1VerificationKey2019"
)

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
		return nil, nil, fmt.Errorf("unsupported did:key type: %s", kt)
	}

	pubKey, privKey, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not generate key for did:key")
	}

	pubKeyBytes, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		return nil, nil, err
	}

	didKey, err := CreateDIDKey(kt, pubKeyBytes)
	if err != nil {
		return nil, nil, err
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
		return nil, err
	}
	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(Base58BTCMultiBase, codec)
	if err != nil {
		return nil, err
	}
	did := DIDKey(fmt.Sprintf("%s:%s", DIDKeyPrefix, encoded))
	return &did, nil
}

// Decode takes a did:key and returns the underlying public key value as bytes, the LD key type, and a possible error
func (d DIDKey) Decode() ([]byte, cryptosuite.LDKeyType, error) {
	parsed := d.Parse()
	if parsed == "" {
		return nil, "", fmt.Errorf("could not decode did:key value: %s", string(d))
	}

	encoding, decoded, err := multibase.Decode(parsed)
	if err != nil {
		return nil, "", err
	}
	if encoding != Base58BTCMultiBase {
		return nil, "", fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", err
	}
	if n != 2 {
		return nil, "", fmt.Errorf("error parsing did:key varint")
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
		return nil, "", fmt.Errorf("unknown multicodec for did:key: %d", multiCodecValue)
	}
}

// Expand turns the DID key into a complaint DID Document
func (d DIDKey) Expand() (*DIDDocument, error) {
	keyReference := "#" + d.Parse()
	id := string(d)

	pubKey, keyType, err := d.Decode()
	if err != nil {
		return nil, err
	}

	verificationMethod, err := constructVerificationMethod(id, keyReference, pubKey, keyType)
	if err != nil {
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
		return nil, errors.Wrap(err, "could not expand key of type JsonWebKey2020")
	}
	pubKeyJWK, err := cryptosuite.ToPublicKeyJWK(standardJWK)
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

// Parse returns the value without the `did:key` prefix
func (d DIDKey) Parse() string {
	split := strings.Split(string(d), DIDKeyPrefix+":")
	if len(split) != 2 {
		return ""
	}
	return split[1]
}

func keyTypeToMultiCodec(kt crypto.KeyType) (multicodec.Code, error) {
	switch kt {
	case crypto.Ed25519:
		return Ed25519MultiCodec, nil
	case crypto.X25519:
		return X25519MultiCodec, nil
	case crypto.Secp256k1:
		return Secp256k1MultiCodec, nil
	case crypto.P256:
		return P256MultiCodec, nil
	case crypto.P384:
		return P384MultiCodec, nil
	case crypto.P521:
		return P521MultiCodec, nil
	case crypto.RSA:
		return RSAMultiCodec, nil
	}
	return 0, fmt.Errorf("unknown multicodec for key type: %s", kt)
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
