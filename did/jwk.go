package did

import (
	gocrypto "crypto"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
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
	pubKeyJWKString := string(pubKeyJWKBytes)

	// 3. Encode string using base64url
	encodedPubKeyJWKString := base64.URLEncoding.EncodeToString([]byte(pubKeyJWKString))

	// 4. Prepend the string with the did:jwk prefix
	didJWK := DIDJWK(fmt.Sprintf("%s:%s", JWKPrefix, encodedPubKeyJWKString))
	return &didJWK, nil
}

// Expand turns the DID JWK into a compliant DID Document
func (d DIDJWK) Expand() (*Document, error) {
	id := d.String()
	return &Document{
		Context:              []string{KnownDIDContext, JWS2020Context},
		ID:                   id,
		VerificationMethod:   []VerificationMethod{},
		Authentication:       nil,
		AssertionMethod:      nil,
		KeyAgreement:         nil,
		CapabilityInvocation: nil,
		CapabilityDelegation: nil,
		Services:             nil,
	}, nil
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
