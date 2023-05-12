package key

import (
	gocrypto "crypto"
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/jorrizza/ed2curve25519"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"

	"github.com/TBD54566975/ssi-sdk/cryptosuite"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"

	"github.com/multiformats/go-varint"
)

type (
	DIDKey string
)

const (
	// Prefix did:key prefix
	Prefix = "did:key"

	// Expansion options

	EnableEncryptionKeyDerivationOption = "EnableEncryptionKeyDerivation"
	PublicKeyFormatOption               = "PublicKeyFormat"
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
	split := strings.Split(string(d), Prefix+":")
	if len(split) != 2 {
		return "", fmt.Errorf("invalid did:key: %s", d)
	}
	return split[1], nil
}

func (DIDKey) Method() did.Method {
	return did.KeyMethod
}

type Option struct {
	Name  string
	Value any
}

var (
	EnableEncryptionKeyDerivation = Option{
		Name:  EnableEncryptionKeyDerivationOption,
		Value: true,
	}

	DisableEncryptionKeyDerivation = Option{
		Name:  EnableEncryptionKeyDerivationOption,
		Value: false,
	}

	PublicKeyFormatJSONWebKey2020 = Option{
		Name:  PublicKeyFormatOption,
		Value: cryptosuite.JSONWebKey2020Type,
	}

	PublicKeyFormatMultibase = Option{
		Name:  PublicKeyFormatOption,
		Value: cryptosuite.MultikeyType,
	}
)

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
	encoded, err := MultibaseEncodedKey(kt, publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not multibase encode key")
	}
	didKey := DIDKey(fmt.Sprintf("%s:%s", Prefix, encoded))
	return &didKey, nil
}

// MultibaseEncodedKey takes a key type and a public key value and returns the multibase encoded key
func MultibaseEncodedKey(kt crypto.KeyType, publicKey []byte) (string, error) {
	multiCodec, err := did.KeyTypeToMultiCodec(kt)
	if err != nil {
		return "", fmt.Errorf("could find mutlicodec for key type<%s>", kt)
	}
	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(did.Base58BTCMultiBase, codec)
	if err != nil {
		return "", errors.Wrap(err, "multibase encoding")
	}
	return encoded, nil
}

// Decode takes a did:key and returns the underlying public key value as bytes, the key type, and a possible error
// https://w3c-ccg.github.io/did-method-key/#document-creation-algorithm
func (d DIDKey) Decode() ([]byte, crypto.KeyType, error) {
	parsed, err := d.Suffix()
	if err != nil {
		return nil, "", errors.Wrap(err, "could not parse did:key")
	}
	if parsed == "" {
		return nil, "", fmt.Errorf("could not decode did:key value: %s", string(d))
	}

	encoding, decoded, err := multibase.Decode(parsed)
	if err != nil {
		return nil, "", errors.Wrap(err, "could not decode did:key")
	}
	if encoding != did.Base58BTCMultiBase {
		return nil, "", fmt.Errorf("expected %d encoding but found %d", did.Base58BTCMultiBase, encoding)
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", err
	}
	if n != 2 {
		return nil, "", errors.New("error parsing did:key varint")
	}

	pubKeyBytes := decoded[n:]
	multiCodecValue := multicodec.Code(multiCodec)
	cryptoKeyType, err := did.MultiCodecToKeyType(multiCodecValue)
	if err != nil {
		return nil, "", errors.Wrap(err, "determining key type")
	}
	return pubKeyBytes, cryptoKeyType, nil
}

// Expand turns the DID key into a compliant DID Document
// Accepts the following options:
//   - EnableEncryptionKeyDerivationOption (default to true)
//   - PublicKeyFormatOption (defaults to JWK)
//
// TODO(gabe) support BLS curves https://github.com/TBD54566975/ssi-sdk/issues/381
func (d DIDKey) Expand(opts ...Option) (*did.Document, error) {
	publicKeyFormat, enableEncryptionDerivation, err := processExpansionOptions(opts...)
	if err != nil {
		return nil, err
	}

	id := string(d)
	suffix, err := d.Suffix()
	if err != nil {
		return nil, errors.Wrap(err, "could not parse did:key")
	}
	pubKey, cryptoKeyType, err := d.Decode()
	if err != nil {
		return nil, errors.Wrap(err, "could not decode did:key")
	}

	var verificationMethod *did.VerificationMethod
	keyID := id + "#" + suffix
	switch publicKeyFormat {
	case cryptosuite.JSONWebKey2020Type:
		verificationMethod, err = did.ConstructJWKVerificationMethod(keyID, id, pubKey, cryptoKeyType)
		if err != nil {
			return nil, errors.Wrapf(err, "could not construct %s verification method", publicKeyFormat)
		}
	case cryptosuite.MultikeyType:
		multiKeyType, err := did.KeyTypeToMultikeyLDType(cryptoKeyType)
		if err != nil {
			return nil, errors.Wrap(err, "could not convert key type to multikey type")
		}
		verificationMethod, err = did.ConstructMultibaseVerificationMethod(keyID, id, pubKey, multiKeyType)
		if err != nil {
			return nil, errors.Wrapf(err, "could not construct %s verification method", publicKeyFormat)
		}
	default:
		return nil, fmt.Errorf("unsupported public key format: %s", publicKeyFormat)
	}

	// always include the first key as a verification method
	verificationMethodSet := []did.VerificationMethodSet{keyID}

	doc := did.Document{
		ID:                   id,
		VerificationMethod:   []did.VerificationMethod{*verificationMethod},
		Authentication:       verificationMethodSet,
		AssertionMethod:      verificationMethodSet,
		CapabilityDelegation: verificationMethodSet,
		CapabilityInvocation: verificationMethodSet,
	}

	// https://w3c-ccg.github.io/did-method-key/#context-creation-algorithm
	contexts := []string{did.KnownDIDContext}
	if publicKeyFormat == cryptosuite.JSONWebKey2020Type {
		contexts = append(contexts, cryptosuite.JSONWebKey2020Context)
	} else {
		switch cryptoKeyType {
		case crypto.SECP256k1:
			contexts = append(contexts, cryptosuite.SECP256k1VerificationKey2019Context)
		case crypto.Ed25519:
			if enableEncryptionDerivation {
				contexts = append(contexts, cryptosuite.X25519KeyAgreementKey2020Context)
			}
			contexts = append(contexts, cryptosuite.Ed25519VerificationKey2020Context)
		case crypto.X25519:
			contexts = append(contexts, cryptosuite.X25519KeyAgreementKey2020Context)
		case crypto.BLS12381G1, crypto.BLS12381G2:
			contexts = append(contexts, cryptosuite.BLS12381G2Key2020Context)
		case crypto.P224, crypto.P256, crypto.P384, crypto.P521:
			contexts = append(contexts, cryptosuite.Multikey2021Context)
		}
	}
	doc.Context = contexts

	// X25519 doesn't have any property except key agreement
	isVerificationMethodX25519Key := false
	if (publicKeyFormat == cryptosuite.JSONWebKey2020Type && verificationMethod.PublicKeyJWK.CRV == string(cryptosuite.X25519)) ||
		(publicKeyFormat == cryptosuite.MultikeyType && (verificationMethod.Type == cryptosuite.X25519KeyAgreementKey2020 ||
			verificationMethod.Type == cryptosuite.X25519KeyAgreementKey2019)) {
		x25519Key = true
		doc.Authentication = nil
		doc.AssertionMethod = nil
		doc.CapabilityDelegation = nil
		doc.CapabilityInvocation = nil
		doc.KeyAgreement = []did.VerificationMethodSet{keyID}
	}

	// https://w3c-ccg.github.io/did-method-key/#derive-encryption-key-algorithm
	// the only case we have to consider is if the verification method is X25519
	if enableEncryptionDerivation && !x25519Key {
		keyAgreementVerificationMethod, keyAgreementVerificationMethodSet, err := generateKeyAgreementVerificationMethod(*verificationMethod)
		if err != nil {
			return nil, errors.Wrap(err, "could not generate key agreement verification method")
		}
		if keyAgreementVerificationMethod != nil {
			doc.VerificationMethod = append(doc.VerificationMethod, *keyAgreementVerificationMethod)
		}
		doc.KeyAgreement = keyAgreementVerificationMethodSet
	}

	return &doc, nil
}

func generateKeyAgreementVerificationMethod(vm did.VerificationMethod) (*did.VerificationMethod, []did.VerificationMethodSet, error) {
	var verificationMethod *did.VerificationMethod
	var verificationMethodSet []did.VerificationMethodSet
	var vmErr error
	if vm.Type == cryptosuite.Ed25519VerificationKey2018 || vm.Type == cryptosuite.Ed25519VerificationKey2020 {
		// convert key to X25519
		base58PubKey, err := base58.Decode(vm.PublicKeyBase58)
		if err != nil {
			return nil, nil, errors.Wrap(err, "decoding base58 public key")
		}
		ed25519PubKey, err := crypto.BytesToPubKey(base58PubKey, crypto.Ed25519)
		if err != nil {
			return nil, nil, errors.Wrap(err, "could not convert base58 public key to ed25519")
		}
		id, x25519Key, err := x25519KeyAndID(vm.Controller, ed25519PubKey.(ed25519.PublicKey))
		if err != nil {
			return nil, nil, errors.Wrap(err, "generating x25519 key and id")
		}
		verificationMethod, vmErr = did.ConstructMultibaseVerificationMethod(id, vm.Controller, x25519Key, cryptosuite.X25519KeyAgreementKey2020)
		verificationMethodSet = []did.VerificationMethodSet{id}
		return verificationMethod, verificationMethodSet, vmErr
	} else if vm.Type == cryptosuite.JSONWebKey2020Type && vm.PublicKeyJWK.KTY == string(cryptosuite.OKP) &&
		vm.PublicKeyJWK.CRV == string(cryptosuite.Ed25519) {
		// convert key to X25519
		ed25519PubKey, err := vm.PublicKeyJWK.ToPublicKey()
		if err != nil {
			return nil, nil, errors.Wrap(err, "could not convert ed25519 public key to x25519")
		}
		id, x25519Key, err := x25519KeyAndID(vm.Controller, ed25519PubKey.(ed25519.PublicKey))
		if err != nil {
			return nil, nil, errors.Wrap(err, "could not generate x25519 key and id")
		}
		verificationMethod, vmErr = did.ConstructJWKVerificationMethod(id, vm.Controller, x25519Key, crypto.X25519)
		verificationMethodSet = []did.VerificationMethodSet{id}
	} else {
		verificationMethodSet = []did.VerificationMethodSet{vm.ID}
	}
	return verificationMethod, verificationMethodSet, vmErr
}

func x25519KeyAndID(id string, ed25519PubKey ed25519.PublicKey) (string, []byte, error) {
	if len(ed25519PubKey) != ed25519.PublicKeySize {
		return "", nil, errors.New("ed25519 public key is not the right size")
	}
	x25519Key := ed2curve25519.Ed25519PublicKeyToCurve25519(ed25519PubKey)
	keyAgreementDIDKey, err := CreateDIDKey(crypto.X25519, x25519Key)
	if err != nil {
		return "", nil, errors.Wrap(err, "could not multibase encode x25519 public key")
	}
	suffix, err := keyAgreementDIDKey.Suffix()
	if err != nil {
		return "", nil, errors.Wrap(err, "could not get suffix from did:key")
	}
	return id + "#" + suffix, x25519Key, nil
}

func processExpansionOptions(opts ...Option) (cryptosuite.LDKeyType, bool, error) {
	publicKeyFormat := cryptosuite.JSONWebKey2020Type
	enableEncryptionKeyDerivation := true
	var ok bool
	for _, opt := range opts {
		switch opt.Name {
		case "":
			continue
		case PublicKeyFormatOption:
			publicKeyFormat, ok = opt.Value.(cryptosuite.LDKeyType)
			if !ok {
				return "", false, fmt.Errorf("invalid public key format option type: %T", opt.Value)
			}

		case EnableEncryptionKeyDerivationOption:
			enableEncryptionKeyDerivation, ok = opt.Value.(bool)
			if !ok {
				return "", false, fmt.Errorf("invalid enable encryption key derivation option type: %T", opt.Value)
			}
		default:
			return "", false, fmt.Errorf("invalid option: %s", opt.Name)
		}
	}
	return publicKeyFormat, enableEncryptionKeyDerivation, nil
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
