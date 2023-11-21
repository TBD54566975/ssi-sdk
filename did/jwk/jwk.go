package jwk

import (
	gocrypto "crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/did"
)

type (
	JWK string
)

const (
	// Prefix did:jwk prefix
	Prefix = "did:jwk"
)

func (d JWK) IsValid() bool {
	_, err := d.Expand()
	return err == nil
}

func (d JWK) String() string {
	return string(d)
}

// Suffix returns the value without the `did:jwk` prefix
func (d JWK) Suffix() (string, error) {
	if suffix, ok := strings.CutPrefix(string(d), Prefix+":"); ok {
		return suffix, nil
	}
	return "", fmt.Errorf("invalid did:jwk: %s", d)
}

func (JWK) Method() did.Method {
	return did.JWKMethod
}

// GenerateDIDJWK takes in a key type value that this library supports and constructs a conformant did:jwk identifier.
func GenerateDIDJWK(kt crypto.KeyType) (gocrypto.PrivateKey, *JWK, error) {
	if !IsSupportedJWKType(kt) {
		return nil, nil, fmt.Errorf("unsupported did:jwk type: %s", kt)
	}

	// 1. Generate a JWK
	pubKey, privKey, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating key for did:jwk")
	}
	// kid not needed since it will be set on expansion
	pubKeyJWK, err := jwx.PublicKeyToPublicKeyJWK(nil, pubKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting public key to JWK")
	}

	// 2. Serialize it into a UTF-8 string
	// 3. Encode string using base64url
	// 4. Prepend the string with the did:jwk prefix
	didJWK, err := CreateDIDJWK(*pubKeyJWK)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating did:jwk")
	}
	return privKey, didJWK, nil
}

// CreateDIDJWK creates a did:jwk from a JWK public key by following the steps in the spec:
// https://github.com/quartzjer/did-jwk/blob/main/spec.md
func CreateDIDJWK(publicKeyJWK jwx.PublicKeyJWK) (*JWK, error) {
	// 2. Serialize it into a UTF-8 string
	pubKeyJWKBytes, err := json.Marshal(publicKeyJWK)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling public key JWK")
	}
	pubKeyJWKStr := string(pubKeyJWKBytes)

	// 3. Encode string using base64url
	encodedPubKeyJWKStr := base64.RawURLEncoding.EncodeToString([]byte(pubKeyJWKStr))

	// 4. Prepend the string with the did:jwk prefix
	didJWK := JWK(fmt.Sprintf("%s:%s", Prefix, encodedPubKeyJWKStr))
	return &didJWK, nil
}

// Expand turns the DID JWK into a compliant DID Document
func (d JWK) Expand() (*did.Document, error) {
	id := d.String()

	if !strings.HasPrefix(id, Prefix) {
		return nil, fmt.Errorf("not a did:jwk DID, invalid prefix: %s", id)
	}

	encodedJWK, err := d.Suffix()
	if err != nil {
		return nil, errors.Wrap(err, "reading suffix")
	}
	decodedPubKeyJWKStr, err := base64.RawURLEncoding.DecodeString(encodedJWK)
	if err != nil {
		return nil, errors.Wrap(err, "decoding did:jwk")
	}

	var pubKeyJWK jwx.PublicKeyJWK
	if err = json.Unmarshal(decodedPubKeyJWKStr, &pubKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling did:jwk")
	}

	keyReference := "#0"
	keyID := id + keyReference

	doc := did.Document{
		Context: []string{did.KnownDIDContext, cryptosuite.JSONWebKey2020Context},
		ID:      id,
		VerificationMethod: []did.VerificationMethod{
			{
				ID:           keyID,
				Type:         cryptosuite.JSONWebKey2020Type,
				Controller:   id,
				PublicKeyJWK: &pubKeyJWK,
			},
		},
		Authentication:       []did.VerificationMethodSet{keyID},
		AssertionMethod:      []did.VerificationMethodSet{keyID},
		KeyAgreement:         []did.VerificationMethodSet{keyID},
		CapabilityInvocation: []did.VerificationMethodSet{keyID},
		CapabilityDelegation: []did.VerificationMethodSet{keyID},
	}

	// If the JWK contains a use property with the value "sig" then the keyAgreement property is not included in the
	// DID Document. If the use value is "enc" then only the keyAgreement property is included in the DID Document.
	switch pubKeyJWK.Use {
	case "sig":
		doc.KeyAgreement = nil
	case "enc":
		doc.Authentication = nil
		doc.AssertionMethod = nil
		doc.CapabilityInvocation = nil
		doc.CapabilityDelegation = nil
	}

	return &doc, nil
}

// IsSupportedJWKType returns if a given key type is supported for the did:jwk method
func IsSupportedJWKType(kt crypto.KeyType) bool {
	jwkTypes := GetSupportedDIDJWKTypes()
	for _, t := range jwkTypes {
		if t == kt {
			return true
		}
	}
	return false
}

// GetSupportedDIDJWKTypes returns all supported did:jwk key types
func GetSupportedDIDJWKTypes() []crypto.KeyType {
	return []crypto.KeyType{crypto.Ed25519, crypto.X25519, crypto.SECP256k1, crypto.P256, crypto.P384, crypto.P521, crypto.RSA}
}
