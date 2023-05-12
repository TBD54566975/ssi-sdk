package jwx

import (
	gocrypto "crypto"
	"fmt"
	"reflect"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
)

// Signer is a struct that contains the key and algorithm used to sign JWTs and produce JWS values
type Signer struct {
	ID string
	PrivateKeyJWK
	gocrypto.PrivateKey
}

// NewJWXSigner creates a new signer from a private key to sign and produce JWS values
func NewJWXSigner(id, kid string, key gocrypto.PrivateKey) (*Signer, error) {
	_, privateKeyJWK, err := PrivateKeyToPrivateKeyJWK(kid, key)
	if err != nil {
		return nil, errors.Wrap(err, "converting private key to JWK")
	}
	return jwxSigner(id, *privateKeyJWK, key)
}

// NewJWXSignerFromJWK creates a new signer from a private key to sign and produce JWS values
func NewJWXSignerFromJWK(id string, key PrivateKeyJWK) (*Signer, error) {
	privateKey, err := key.ToPrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, "converting JWK to private key")
	}
	return jwxSigner(id, key, privateKey)
}

func jwxSigner(id string, jwk PrivateKeyJWK, key gocrypto.PrivateKey) (*Signer, error) {
	if id == "" {
		return nil, errors.New("id is required")
	}
	if jwk.IsEmpty() {
		return nil, errors.New("jwk is required")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if jwk.ALG == "" {
		alg, err := AlgFromKeyAndCurve(jwk.KTY, jwk.CRV)
		if err != nil {
			return nil, errors.Wrap(err, "getting alg from key and curve")
		}
		jwk.ALG = alg
	}
	if !IsSupportedJWXSigningVerificationAlgorithm(jwk.ALG) && !IsExperimentalJWXSigningVerificationAlgorithm(jwk.ALG) {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", jwk.ALG)
	}
	if convertedPrivKey, ok := privKeyForJWX(key); ok {
		key = convertedPrivKey
	}
	return &Signer{ID: id, PrivateKeyJWK: jwk, PrivateKey: key}, nil
}

// some key types need to be converted to work with our signing library, such as
// secp256k1 keys, which need to be converted to ecdsa keys
func privKeyForJWX(key gocrypto.PrivateKey) (gocrypto.PrivateKey, bool) {
	for reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PrivateKey)
	}
	switch k := key.(type) {
	case secp256k1.PrivateKey:
		return *k.ToECDSA(), true
	default:
		return nil, false
	}
}

// ToVerifier converts a signer to a verifier, where the passed in verifiedID is the intended ID of the verifier for
// `aud` validation
func (s *Signer) ToVerifier(verifierID string) (*Verifier, error) {
	publicKeyJWK := s.PrivateKeyJWK.ToPublicKeyJWK()
	return NewJWXVerifierFromJWK(verifierID, publicKeyJWK)
}

// Verifier is a struct that contains the key and algorithm used to verify JWTs and JWS signatures
type Verifier struct {
	ID string
	PublicKeyJWK
	publicKey gocrypto.PublicKey
}

// NewJWXVerifier creates a new verifier from a public key to verify JWTs and JWS signatures
func NewJWXVerifier(id, kid string, key gocrypto.PublicKey) (*Verifier, error) {
	publicKeyJWK, err := PublicKeyToPublicKeyJWK(kid, key)
	if err != nil {
		return nil, errors.Wrap(err, "converting public key to JWK")
	}
	return jwxVerifier(id, *publicKeyJWK, key)
}

// NewJWXVerifierFromJWK creates a new verifier from a public key to verify JWTs and JWS signatures
func NewJWXVerifierFromJWK(id string, key PublicKeyJWK) (*Verifier, error) {
	pubKey, err := key.ToPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "converting JWK to public key")
	}
	return jwxVerifier(id, key, pubKey)
}

func jwxVerifier(id string, jwk PublicKeyJWK, key gocrypto.PublicKey) (*Verifier, error) {
	if id == "" {
		return nil, errors.New("id is required")
	}
	if jwk.IsEmpty() {
		return nil, errors.New("jwk is required")
	}
	if key == nil {
		return nil, errors.New("key is required")
	}
	if jwk.ALG == "" {
		alg, err := AlgFromKeyAndCurve(jwk.KTY, jwk.CRV)
		if err != nil {
			return nil, errors.Wrap(err, "getting alg from key and curve")
		}
		jwk.ALG = alg
	}
	if !IsSupportedJWXSigningVerificationAlgorithm(jwk.ALG) && !IsExperimentalJWXSigningVerificationAlgorithm(jwk.ALG) {
		return nil, fmt.Errorf("unsupported signing/verification algorithm: %s", jwk.ALG)
	}
	if convertedPubKey, ok := pubKeyForJWX(key); ok {
		key = convertedPubKey
	}
	return &Verifier{ID: id, PublicKeyJWK: jwk, publicKey: key}, nil
}

// some key types need to be converted to work with our signing library, such as
// secp256k1 keys, which need to be converted to ecdsa keys
func pubKeyForJWX(key gocrypto.PublicKey) (gocrypto.PublicKey, bool) {
	for reflect.ValueOf(key).Kind() == reflect.Ptr {
		key = reflect.ValueOf(key).Elem().Interface().(gocrypto.PublicKey)
	}
	switch k := key.(type) {
	case secp256k1.PublicKey:
		return *k.ToECDSA(), true
	default:
		return nil, false
	}
}

// SignWithDefaults takes a set of JWT keys and values to add to a JWT before singing them with
// the key defined in the signer. Automatically sets iss and iat
func (s *Signer) SignWithDefaults(kvs map[string]any) ([]byte, error) {
	t := jwt.New()

	// set known default values, which can be overridden by the kvs
	iss := s.ID
	if iss != "" {
		if err := t.Set(jwt.IssuerKey, iss); err != nil {
			return nil, errors.Wrapf(err, "setting iss with provided value: %s", iss)
		}
	}
	iat := time.Now().Unix()
	if err := t.Set(jwt.IssuedAtKey, iat); err != nil {
		return nil, errors.Wrapf(err, "setting iat with value: %d", iat)
	}

	for k, v := range kvs {
		if err := t.Set(k, v); err != nil {
			return nil, errors.Wrapf(err, "setting %s to value: %v", k, v)
		}
	}
	hdrs := jws.NewHeaders()
	if s.KID != "" {
		if err := hdrs.Set(jws.KeyIDKey, s.KID); err != nil {
			return nil, errors.Wrap(err, "setting KID protected header")
		}
	}
	return jwt.Sign(t, jwt.WithKey(jwa.SignatureAlgorithm(s.ALG), s.PrivateKey, jws.WithProtectedHeaders(hdrs)))
}

// Verify parses a token given the verifier's known algorithm and key, and returns an error, which is nil upon success
func (v *Verifier) Verify(token string) error {
	if _, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.SignatureAlgorithm(v.ALG), v.publicKey)); err != nil {
		return errors.Wrap(err, "verifying JWT")
	}
	return nil
}

// Parse attempts to turn a string into a jwt.Token
func (*Verifier) Parse(token string) (jws.Headers, jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing JWT")
	}
	headers, err := GetJWSHeaders([]byte(token))
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting JWT headers")
	}
	return headers, parsed, nil
}

// VerifyAndParse attempts to turn a string into a jwt.Token and verify its signature using the verifier
func (v *Verifier) VerifyAndParse(token string) (jws.Headers, jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.SignatureAlgorithm(v.ALG), v.publicKey))
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing and verifying JWT")
	}
	headers, err := GetJWSHeaders([]byte(token))
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting JWT headers")
	}
	return headers, parsed, nil
}

// AlgFromKeyAndCurve returns the supported JSON Web Algorithm for signing for a given key type and curve pair
// The curve parameter is optional (e.g. "") as in the case of RSA.
func AlgFromKeyAndCurve(kty, crv string) (string, error) {
	if kty == jwa.RSA.String() {
		return jwa.PS256.String(), nil
	} else if kty == DilithiumKTY {
		return "", errors.New("dilithium alg should already be set")
	}

	if crv == "" {
		return "", errors.New("crv must be specified for non-RSA key types")
	}

	curve := crv
	if kty == jwa.OKP.String() {
		switch curve {
		case jwa.X25519.String():
			return jwa.X25519.String(), nil
		case jwa.Ed25519.String():
			return jwa.EdDSA.String(), nil
		default:
			return "", fmt.Errorf("unsupported OKP jwt curve: %s", curve)
		}
	}

	if kty == jwa.EC.String() {
		switch curve {
		case crypto.SECP256k1.String():
			return jwa.ES256K.String(), nil
		case jwa.P256.String():
			return jwa.ES256.String(), nil
		case jwa.P384.String():
			return jwa.ES384.String(), nil
		case jwa.P521.String():
			return jwa.ES512.String(), nil
		default:
			return "", fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return "", fmt.Errorf("unsupported key type: %s", kty)
}

// IsSupportedJWXSigningVerificationAlgorithm returns true if the algorithm is supported for signing or verifying JWXs
func IsSupportedJWXSigningVerificationAlgorithm(algorithm string) bool {
	for _, supported := range GetSupportedJWXSigningVerificationAlgorithms() {
		if algorithm == supported {
			return true
		}
	}
	return false
}

// GetSupportedJWXSigningVerificationAlgorithms returns a list of supported signing and verifying algorithms for JWXs
func GetSupportedJWXSigningVerificationAlgorithms() []string {
	return []string{
		jwa.PS256.String(),
		jwa.ES256.String(),
		jwa.ES256K.String(),
		jwa.ES384.String(),
		jwa.ES512.String(),
		jwa.EdDSA.String(),
	}
}

// IsExperimentalJWXSigningVerificationAlgorithm returns true if the algorithm is supported for experimental signing or verifying JWXs
func IsExperimentalJWXSigningVerificationAlgorithm(algorithm string) bool {
	for _, supported := range GetExperimentalJWXSigningVerificationAlgorithms() {
		if algorithm == supported {
			return true
		}
	}
	return false
}

// GetExperimentalJWXSigningVerificationAlgorithms returns a list of experimental signing and verifying algorithms for JWXs
func GetExperimentalJWXSigningVerificationAlgorithms() []string {
	return []string{
		DilithiumMode2Alg.String(),
		DilithiumMode3Alg.String(),
		DilithiumMode5Alg.String(),
	}
}
