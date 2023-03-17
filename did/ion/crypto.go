package ion

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"

	sdkcrypto "github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/gowebpki/jcs"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/multiformats/go-multihash"
	"github.com/sirupsen/logrus"
)

// HashEncode hashes given data according to the protocol's hashing process
// https://identity.foundation/sidetree/spec/#hashing-process
func HashEncode(data []byte) (string, error) {
	hashed, err := Multihash(data)
	if err != nil {
		return "", err
	}
	return Encode(hashed), nil
}

// Multihash https://multiformats.io/multihash/
func Multihash(data []byte) ([]byte, error) {
	// first hash using the given hashing algorithm
	hashed := sha256.Sum256(data)

	// next encode as a mulithash
	multiHashed, err := multihash.Encode(hashed[:], multihash.SHA2_256)
	if err != nil {
		logrus.WithError(err).Error("could not multi-hash the given data")
		return nil, err
	}
	return multiHashed, nil
}

// Encode encodes according to the encoding scheme of the sidetree spec
func Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// EncodeString encodes a string according to the encoding scheme of the sidetree spec
func EncodeString(data string) string {
	return Encode([]byte(data))
}

// Decode decodes according to the encoding scheme of the sidetree spec
func Decode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}

// Canonicalize transforms JSON according to the protocol's JSON Canonicalization Scheme
// https://identity.foundation/sidetree/spec/#json-canonicalization-scheme
func Canonicalize(data []byte) ([]byte, error) {
	return jcs.Transform(data)
}

// CanonicalizeAny transforms JSON according to the protocol's JSON Canonicalization Scheme
// https://identity.foundation/sidetree/spec/#json-canonicalization-scheme
func CanonicalizeAny(data any) ([]byte, error) {
	anyBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return Canonicalize(anyBytes)
}

// Commit creates a public key commitment according to the steps defined in the protocol
// https://identity.foundation/sidetree/spec/#public-key-commitment-scheme
func Commit(key crypto.PublicKey) (reveal, commitment string, err error) {
	// 1. Encode the public key into the form of a valid JWK.
	rawKey, err := jwk.FromRaw(key)
	if err != nil {
		logrus.WithError(err).Error("could not parse public key as a JWK")
		return "", "", err
	}
	keyBytes, err := json.Marshal(rawKey)
	if err != nil {
		logrus.WithError(err).Error("could not marshal jwk to JSON")
		return "", "", err
	}

	// 2. Canonicalize the JWK encoded public key using the implementation’s JSON_CANONICALIZATION_SCHEME.
	canonicalKey, err := Canonicalize(keyBytes)
	if err != nil {
		logrus.WithError(err).Error("could not canonicalize JWK")
		return "", "", err
	}

	// 3. Use the implementation’s HASH_PROTOCOL to Multihash the canonicalized public key to generate the REVEAL_VALUE,
	// then Multihash the resulting Multihash value again using the implementation’s HASH_PROTOCOL to produce
	// the public key commitment.

	revealValue, err := Multihash(canonicalKey)
	if err != nil {
		logrus.WithError(err).Error("could not generate reveal value")
		return "", "", err
	}
	commitment, err = HashEncode([]byte(revealValue))
	if err != nil {
		logrus.WithError(err).Error("could not generate commitment value")
		return "", "", err
	}

	return reveal, commitment, nil
}

// CommitJWK creates a public key commitment according to the steps defined in the protocol
// https://identity.foundation/sidetree/spec/#public-key-commitment-scheme
func CommitJWK(key sdkcrypto.PublicKeyJWK) (reveal, commitment string, err error) {
	gotJWK, err := sdkcrypto.JWKFromPublicKeyJWK(key)
	if err != nil {
		return "", "", err
	}
	return Commit(gotJWK)
}
