package did

import (
	"context"
	gocrypto "crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
)

type (
	DIDJWK string
)

const (
	// JWKPrefix did:jwk prefix
	JWKPrefix = "did:jwk"
)

func (d DIDJWK) IsValid() bool {
	_, err := d.Expand()
	return err == nil
}

func (d DIDJWK) String() string {
	return string(d)
}

// Suffix returns the value without the `did:jwk` prefix
func (d DIDJWK) Suffix() (string, error) {
	split := strings.Split(string(d), JWKPrefix+":")
	if len(split) != 2 {
		return "", fmt.Errorf("invalid did:jwk: %s", d)
	}
	return split[1], nil
}

func (DIDJWK) Method() Method {
	return JWKMethod
}

// GenerateDIDJWK takes in a key type value that this library supports and constructs a conformant did:jwk identifier.
func GenerateDIDJWK(kt crypto.KeyType) (gocrypto.PrivateKey, *DIDJWK, error) {
	if !isSupportedJWKType(kt) {
		return nil, nil, fmt.Errorf("unsupported did:jwk type: %s", kt)
	}

	// 1. Generate a JWK
	pubKey, privKey, err := crypto.GenerateKeyByKeyType(kt)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generating key for did:jwk")
	}
	pubKeyJWK, err := crypto.PublicKeyToJWK(pubKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "converting public key to JWK")
	}

	// 2. Serialize it into a UTF-8 string
	// 3. Encode string using base64url
	// 4. Prepend the string with the did:jwk prefix
	didJWK, err := CreateDIDJWK(pubKeyJWK)
	if err != nil {
		return nil, nil, errors.Wrap(err, "creating did:jwk")
	}
	return privKey, didJWK, nil
}

// CreateDIDJWK creates a did:jwk from a JWK public key by following the steps in the spec:
// https://github.com/quartzjer/did-jwk/blob/main/spec.md
func CreateDIDJWK(publicKeyJWK jwk.Key) (*DIDJWK, error) {
	// 2. Serialize it into a UTF-8 string
	pubKeyJWKBytes, err := json.Marshal(publicKeyJWK)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling public key JWK")
	}
	pubKeyJWKStr := string(pubKeyJWKBytes)

	// 3. Encode string using base64url
	encodedPubKeyJWKStr := base64.URLEncoding.EncodeToString([]byte(pubKeyJWKStr))

	// 4. Prepend the string with the did:jwk prefix
	didJWK := DIDJWK(fmt.Sprintf("%s:%s", JWKPrefix, encodedPubKeyJWKStr))
	return &didJWK, nil
}

// Expand turns the DID JWK into a compliant DID Document
func (d DIDJWK) Expand() (*Document, error) {
	id := d.String()

	encodedJWK, err := d.Suffix()
	if err != nil {
		return nil, fmt.Errorf("invalid did:jwk: %s", d)
	}
	decodedPubKeyJWKStr, err := base64.URLEncoding.DecodeString(encodedJWK)
	if err != nil {
		return nil, errors.Wrap(err, "decoding did:jwk")
	}

	var pubKeyJWK crypto.PublicKeyJWK
	if err = json.Unmarshal(decodedPubKeyJWKStr, &pubKeyJWK); err != nil {
		return nil, errors.Wrap(err, "unmarshalling did:jwk")
	}

	keyReference := "#0"
	keyID := id + keyReference

	doc := Document{
		Context: []string{KnownDIDContext, JWS2020Context},
		ID:      id,
		VerificationMethod: []VerificationMethod{
			{
				ID:           keyID,
				Type:         cryptosuite.JSONWebKey2020Type,
				Controller:   id,
				PublicKeyJWK: &pubKeyJWK,
			},
		},
		Authentication:       []VerificationMethodSet{keyID},
		AssertionMethod:      []VerificationMethodSet{keyID},
		KeyAgreement:         []VerificationMethodSet{keyID},
		CapabilityInvocation: []VerificationMethodSet{keyID},
		CapabilityDelegation: []VerificationMethodSet{keyID},
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

func isSupportedJWKType(kt crypto.KeyType) bool {
	jwkTypes := GetSupportedDIDJWKTypes()
	for _, t := range jwkTypes {
		if t == kt {
			return true
		}
	}
	return false
}

func GetSupportedDIDJWKTypes() []crypto.KeyType {
	return []crypto.KeyType{crypto.Ed25519, crypto.X25519, crypto.SECP256k1, crypto.P256, crypto.P384, crypto.P521, crypto.RSA}
}

type JWKResolver struct{}

var _ Resolver = (*JWKResolver)(nil)

func (JWKResolver) Resolve(_ context.Context, did string, _ ...ResolutionOption) (*ResolutionResult, error) {
	if !strings.HasPrefix(did, JWKPrefix) {
		return nil, fmt.Errorf("not a did:jwk DID: %s", did)
	}
	didJWK := DIDJWK(did)
	doc, err := didJWK.Expand()
	if err != nil {
		return nil, errors.Wrapf(err, "could not expand did:jwk DID: %s", did)
	}
	return &ResolutionResult{Document: *doc}, nil
}

func (JWKResolver) Methods() []Method {
	return []Method{JWKMethod}
}
