package did

import (
	"context"
	gocrypto "crypto"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/mr-tron/base58"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-varint"
	"github.com/pkg/errors"
)

// ResolveKeyForDID resolves a public key from a DID for a given KID.
func ResolveKeyForDID(ctx context.Context, resolver Resolver, did, kid string) (gocrypto.PublicKey, error) {
	if resolver == nil {
		return nil, errors.New("resolver cannot be empty")
	}
	resolved, err := resolver.Resolve(ctx, did, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving DID: %s", did)
	}

	// next, get the verification information (key) from the did document
	pubKey, err := GetKeyFromVerificationMethod(resolved.Document, kid)
	if err != nil {
		return nil, errors.Wrapf(err, "getting verification information from DID Document: %s", did)
	}
	return pubKey, err
}

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
	maybeKID1 := kid                            // the kid == the kid
	maybeKID2 := fmt.Sprintf("#%s", kid)        // the kid == the fragment with a #
	maybeKID3 := fmt.Sprintf("%s#%s", did, kid) // the kid == the DID ID + the fragment with a #
	maybeKID4 := fmt.Sprintf("%s%s", did, kid)  // the kid == the DID ID + the fragment without a #
	return targetID == maybeKID1 || targetID == maybeKID2 || targetID == maybeKID3 || targetID == maybeKID4
}

func extractKeyFromVerificationMethod(method VerificationMethod) (gocrypto.PublicKey, error) {
	switch {
	case method.PublicKeyMultibase != "":
		pubKeyBytes, multiBaseErr := multibaseToPubKeyBytes(method.PublicKeyMultibase)
		if multiBaseErr != nil {
			return nil, errors.Wrap(multiBaseErr, "converting multibase key")
		}
		return cryptosuite.PubKeyBytesToTypedKey(pubKeyBytes, method.Type)
	case method.PublicKeyBase58 != "":
		pubKeyDecoded, b58Err := base58.Decode(method.PublicKeyBase58)
		if b58Err != nil {
			return nil, errors.Wrap(b58Err, "decoding base58 key")
		}
		return cryptosuite.PubKeyBytesToTypedKey(pubKeyDecoded, method.Type)
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

// multibaseToPubKey converts a multibase encoded public key to public key bytes for known multibase encodings
func multibaseToPubKeyBytes(mb string) ([]byte, error) {
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

// Encodes the public key provided
// Using a multi-codec encoding.
func encodePublicKeyWithKeyMultiCodecType(kt crypto.KeyType, pubKey gocrypto.PublicKey) (string, error) {
	if !isSupportedKeyType(kt) {
		return "", errors.Wrap(util.UnsupportedError, "not a supported key type")
	}

	publicKey, err := crypto.PubKeyToBytes(pubKey)
	if err != nil {
		return "", err
	}

	multiCodec, err := keyTypeToMultiCodec(kt)
	if err != nil {
		return "", err
	}

	prefix := varint.ToUvarint(uint64(multiCodec))
	codec := append(prefix, publicKey...)
	encoded, err := multibase.Encode(PeerEncNumBasis, codec)
	if err != nil {
		return "", err
	}

	return encoded, nil
}

func decodeEncodedKey(d string) ([]byte, cryptosuite.LDKeyType, crypto.KeyType, error) {
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
	ldKeyType, err := codecToLDKeyType(multiCodecValue)
	if err != nil {
		return nil, "", "", errors.Wrap(err, "codec to ld key type")
	}

	cryptoKeyType, err := codecToKeyType(multiCodecValue)
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

	if encoding != Base58BTCMultiBase {
		err := fmt.Errorf("expected %d encoding but found %d", Base58BTCMultiBase, encoding)
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

func keyTypeToMultiCodec(kt crypto.KeyType) (multicodec.Code, error) {
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
