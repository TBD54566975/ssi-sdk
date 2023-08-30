package did

import (
	gocrypto "crypto"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/cryptosuite/jws2020"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
)

const (
	// Multicodec reference https://github.com/multiformats/multicodec/blob/master/table.csv

	Ed25519MultiCodec   = multicodec.Ed25519Pub
	X25519MultiCodec    = multicodec.X25519Pub
	SECP256k1MultiCodec = multicodec.Secp256k1Pub
	P256MultiCodec      = multicodec.P256Pub
	P384MultiCodec      = multicodec.P384Pub
	P521MultiCodec      = multicodec.P521Pub
	RSAMultiCodec       = multicodec.RsaPub
	SHA256MultiCodec    = multicodec.Sha2_256
)

// GetKeyFromVerificationMethod resolves a DID and provides a kid and public key needed for data verification
// it is possible that a DID has multiple verification methods, in which case a kid must be provided, otherwise
// resolution will fail.
// A KID can be fully qualified (e.g. did:example:123#key-1) or just the fragment (e.g. key-1, #key-1)
// Some DIDs, like did:key, use the entire DID as the KID, so we need to handle all three cases.
func GetKeyFromVerificationMethod(did Document, kid string) (gocrypto.PublicKey, error) {
	if did.IsEmpty() {
		return nil, errors.New("did doc cannot be empty")
	}
	if kid == "" {
		return nil, errors.Errorf("kid is required for did: %s", did.ID)
	}

	verificationMethods := did.VerificationMethod
	if len(verificationMethods) == 0 {
		return nil, errors.Errorf("did<%s> has no verification methods", did.ID)
	}

	for _, method := range verificationMethods {
		// make sure the kid matches the verification method
		if matchesKIDConstruction(did.ID, kid, method.ID) {
			return extractKeyFromVerificationMethod(method)
		}
	}

	return nil, errors.Errorf("did<%s> has no verification methods with kid: %s", did.ID, kid)
}

// matchesKIDConstruction checks if the targetID matches possible combinations of the did and kid
func matchesKIDConstruction(did, kid, targetID string) bool {
	maybeKID1 := kid                                // the kid == the kid
	maybeKID2 := fmt.Sprintf("#%s", kid)            // the kid == the fragment with a #
	maybeKID3 := fmt.Sprintf("%s#%s", did, kid)     // the kid == the DID ID + the fragment with a #
	maybeKID4 := fmt.Sprintf("%s%s", did, kid)      // the kid == the DID ID + the fragment without a #
	maybeKID5, found := strings.CutPrefix(kid, did) // the kid == the did

	var maybeKID6 string // the kid == the did with a fragment, but the doc only references the fragment without a #
	var maybeKID7 string // the kid == the did with a fragment, but the doc only references the fragment with a #
	fullyQualifiedKIDIndex := strings.LastIndex(kid, "#")
	if fullyQualifiedKIDIndex > 0 {
		maybeKID6 = kid[fullyQualifiedKIDIndex:]   // the kid == the fragment with a #
		maybeKID7 = kid[fullyQualifiedKIDIndex+1:] // the kid == the fragment without a #
	}

	return targetID == maybeKID1 || targetID == maybeKID2 || targetID == maybeKID3 || targetID == maybeKID4 ||
		(found && targetID == maybeKID5) || targetID == maybeKID6 || targetID == maybeKID7
}

func extractKeyFromVerificationMethod(method VerificationMethod) (gocrypto.PublicKey, error) {
	switch {
	case method.PublicKeyMultibase != "":
		pubKeyBytes, multiBaseErr := MultiBaseToPubKeyBytes(method.PublicKeyMultibase)
		if multiBaseErr != nil {
			return nil, errors.Wrap(multiBaseErr, "converting multibase key")
		}
		return jws2020.PubKeyBytesToTypedKey(pubKeyBytes, method.Type)
	case method.PublicKeyBase58 != "":
		pubKeyDecoded, b58Err := base58.Decode(method.PublicKeyBase58)
		if b58Err != nil {
			return nil, errors.Wrap(b58Err, "decoding base58 key")
		}
		return jws2020.PubKeyBytesToTypedKey(pubKeyDecoded, method.Type)
	case method.PublicKeyJWK != nil:
		jwkBytes, jwkErr := json.Marshal(method.PublicKeyJWK)
		if jwkErr != nil {
			return nil, errors.Wrap(jwkErr, "marshalling jwk")
		}
		parsed, parseErr := jwk.ParseKey(jwkBytes)
		if parseErr != nil {
			return nil, errors.Wrap(parseErr, "parsing jwk")
		}
		var pubKey gocrypto.PublicKey
		if err := parsed.Raw(&pubKey); err != nil {
			return nil, errors.Wrap(err, "getting raw jwk")
		}
		return pubKey, nil
	}
	return nil, errors.New("no public key found in verification method")
}

// MultiBaseToPubKeyBytes converts a multibase encoded public key to public key bytes for known multibase encodings
func MultiBaseToPubKeyBytes(mb string) ([]byte, error) {
	if mb == "" {
		return nil, errors.New("multibase key cannot be empty")
	}

	encoding, decoded, err := multibase.Decode(mb)
	if err != nil {
		return nil, errors.Wrap(err, "decoding multibase key")
	}
	if encoding != Base58BTCMultiBase {
		return nil, fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	_, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing multibase varint")
	}
	if n != 2 {
		return nil, errors.New("error parsing multibase varint")
	}
	pubKeyBytes := decoded[n:]
	return pubKeyBytes, nil
}

func KeyTypeToMultiCodec(kt crypto.KeyType) (multicodec.Code, error) {
	switch kt {
	case crypto.Ed25519:
		return Ed25519MultiCodec, nil
	case crypto.X25519:
		return X25519MultiCodec, nil
	case crypto.SECP256k1:
		return SECP256k1MultiCodec, nil
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

func MultiCodecToKeyType(codec multicodec.Code) (crypto.KeyType, error) {
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

// MultiCodecToLDKeyType goes from a multicodec to LD key type
func MultiCodecToLDKeyType(codec multicodec.Code) (cryptosuite.LDKeyType, error) {
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

// DecodeMultibaseEncodedKey turns a multibase encoded key to a key and its key type
func DecodeMultibaseEncodedKey(d string) ([]byte, cryptosuite.LDKeyType, crypto.KeyType, error) {
	encoding, decoded, err := multibase.Decode(d)
	if err != nil {
		return nil, "", "", err
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
	ldKeyType, err := MultiCodecToLDKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "codec to ld key type")
	}

	cryptoKeyType, err := MultiCodecToKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "codec to key type")
	}

	return pubKeyBytes, ldKeyType, cryptoKeyType, nil
}

// DecodeMultibasePublicKeyWithType decodes public key with an LD Key Type
func DecodeMultibasePublicKeyWithType(data []byte) ([]byte, cryptosuite.LDKeyType, error) {
	encoding, decoded, err := multibase.Decode(string(data))
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to decode public key")
	}

	if encoding != Base58BTCMultiBase {
		return nil, "", fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
	}

	// n = # bytes for the int, which we expect to be two from our multicodec
	multiCodec, n, err := varint.FromUvarint(decoded)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to decode public key from varint")
	}

	pubKeyBytes := decoded[n:]
	multiCodecValue := multicodec.Code(multiCodec)
	switch multiCodecValue {
	case Ed25519MultiCodec:
		return pubKeyBytes, cryptosuite.Ed25519VerificationKey2020, nil
	case X25519MultiCodec:
		return pubKeyBytes, cryptosuite.X25519KeyAgreementKey2020, nil
	case SHA256MultiCodec:
		return pubKeyBytes, cryptosuite.Ed25519VerificationKey2020, nil
	case SECP256k1MultiCodec:
		return pubKeyBytes, cryptosuite.ECDSASECP256k1VerificationKey2019, nil
	case P256MultiCodec, P384MultiCodec, P521MultiCodec, RSAMultiCodec:
		return pubKeyBytes, cryptosuite.JSONWebKey2020Type, nil
	default:
		return nil, "", fmt.Errorf("unknown multicodec for did:peer: %d", multiCodecValue)
	}
}

// ConstructJWKVerificationMethod builds a DID verification method with a known LD key type as a JWK
func ConstructJWKVerificationMethod(id, controller string, pubKeyBytes []byte, cryptoKeyType crypto.KeyType) (*VerificationMethod, error) {
	// TODO(gabe): consider exposing compression as an option instead of a default
	pubKey, err := crypto.BytesToPubKey(pubKeyBytes, cryptoKeyType, crypto.ECDSACompressed)
	if err != nil {
		return nil, errors.Wrap(err, "converting bytes to public key")
	}

	pubKeyJWK, err := jwx.PublicKeyToPublicKeyJWK(controller, pubKey)
	if err != nil {
		return nil, errors.Wrap(err, "could convert did:key to PublicKeyJWK")
	}

	return &VerificationMethod{
		ID:           id,
		Type:         cryptosuite.JSONWebKey2020Type,
		Controller:   controller,
		PublicKeyJWK: pubKeyJWK,
	}, nil
}

// ConstructMultibaseVerificationMethod builds a DID verification method with a known LD key type as a multibase encoded key
func ConstructMultibaseVerificationMethod(id, controller string, pubKey []byte, keyType cryptosuite.LDKeyType) (*VerificationMethod, error) {
	return &VerificationMethod{
		ID:              id,
		Type:            keyType,
		Controller:      controller,
		PublicKeyBase58: base58.Encode(pubKey),
	}, nil
}

// FullyQualifiedVerificationMethodID returns a fully qualified URL for a verification method.
func FullyQualifiedVerificationMethodID(did, verificationMethodID string) string {
	if strings.HasPrefix(verificationMethodID, "did:") {
		return verificationMethodID
	}
	if strings.HasPrefix(verificationMethodID, "#") {
		return did + verificationMethodID
	}
	return did + "#" + verificationMethodID
}
