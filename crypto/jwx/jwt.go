package jwx

import (
	gocrypto "crypto"
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
)

// Signer is a struct that contains the key and algorithm used to sign JWTs and produce JWS values
type Signer struct {
	ID string
	jwa.SignatureAlgorithm
	jwk.Key
}

// NewJWXSigner creates a new signer from a private key to sign and produce JWS values
// TODO(gabe) support keys not in jwk.Key https://github.com/TBD54566975/ssi-sdk/issues/365
func NewJWXSigner(id, kid string, key gocrypto.PrivateKey) (*Signer, error) {
	privateKeyJWK, err := PrivateKeyToJWK(key)
	if err != nil {
		return nil, err
	}
	return NewJWXSignerFromKey(id, kid, privateKeyJWK)
}

// NewJWXSignerFromJWK creates a new signer from a private key to sign and produce JWS values
func NewJWXSignerFromJWK(id, kid string, key PrivateKeyJWK) (*Signer, error) {
	gotJWK, alg, err := jwxSigner(id, kid, key)
	if err != nil {
		return nil, err
	}
	if !IsSupportedJWXSigningVerificationAlgorithm(*alg) {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
	return &Signer{
		ID:                 id,
		SignatureAlgorithm: *alg,
		Key:                gotJWK,
	}, nil
}

// NewJWXSignerFromKey creates a new signer from a private key to sign and produce JWS values
func NewJWXSignerFromKey(id, kid string, key jwk.Key) (*Signer, error) {
	gotJWK, alg, err := jwxSignerFromKey(id, kid, key)
	if err != nil {
		return nil, err
	}
	if !IsSupportedJWXSigningVerificationAlgorithm(*alg) {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
	return &Signer{ID: id, SignatureAlgorithm: *alg, Key: gotJWK}, nil
}

// ToVerifier converts a signer to a verifier, where the passed in verifiedID is the intended ID of the verifier for
// `aud` validation
func (s *Signer) ToVerifier(verifierID string) (*Verifier, error) {
	key, err := s.Key.PublicKey()
	if err != nil {
		return nil, err
	}
	return NewJWXVerifierFromKey(verifierID, key)
}

// Verifier is a struct that contains the key and algorithm used to verify JWTs and JWS signatures
type Verifier struct {
	ID string
	jwk.Key
}

// NewJWXVerifier creates a new verifier from a public key to verify JWTs and JWS signatures
// TODO(gabe) support keys not in jwk.Key https://github.com/TBD54566975/ssi-sdk/issues/365
func NewJWXVerifier(id string, key gocrypto.PublicKey) (*Verifier, error) {
	privateKeyJWK, err := PublicKeyToJWK(key)
	if err != nil {
		return nil, err
	}
	return NewJWXVerifierFromKey(id, privateKeyJWK)
}

// NewJWXVerifierFromJWK creates a new verifier from a public key to verify JWTs and JWS signatures
func NewJWXVerifierFromJWK(id string, key PublicKeyJWK) (*Verifier, error) {
	gotJWK, alg, err := jwxVerifier(id, key)
	if err != nil {
		return nil, err
	}
	if !IsSupportedJWXSigningVerificationAlgorithm(*alg) {
		return nil, fmt.Errorf("unsupported signing/verification algorithm: %s", alg)
	}
	return &Verifier{ID: id, Key: gotJWK}, nil
}

// NewJWXVerifierFromKey creates a new verifier from a public key to verify JWTs and JWS signatures
func NewJWXVerifierFromKey(id string, key jwk.Key) (*Verifier, error) {
	gotJWK, alg, err := jwkVerifierFromKey(id, key)
	if err != nil {
		return nil, err
	}
	if !IsSupportedJWXSigningVerificationAlgorithm(*alg) {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
	return &Verifier{ID: id, Key: gotJWK}, nil
}

func jwxSigner(id, kid string, key PrivateKeyJWK) (jwk.Key, *jwa.SignatureAlgorithm, error) {
	return jwxSignerVerifier(id, kid, key)
}

func jwxSignerFromKey(id, kid string, key jwk.Key) (jwk.Key, *jwa.SignatureAlgorithm, error) {
	return jwxSignerVerifier(id, kid, key)
}

func jwxVerifier(id string, key PublicKeyJWK) (jwk.Key, *jwa.SignatureAlgorithm, error) {
	return jwxSignerVerifier(id, "", key)
}

func jwkVerifierFromKey(id string, key jwk.Key) (jwk.Key, *jwa.SignatureAlgorithm, error) {
	return jwxSignerVerifier(id, "", key)
}

func jwxSignerVerifier(id, kid string, key any) (jwk.Key, *jwa.SignatureAlgorithm, error) {
	jwkBytes, err := json.Marshal(key)
	if err != nil {
		return nil, nil, err
	}
	parsedKey, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, nil, err
	}
	crv, err := GetCRVFromJWK(parsedKey)
	if err != nil {
		return nil, nil, err
	}
	alg, err := AlgFromKeyAndCurve(parsedKey.KeyType(), jwa.EllipticCurveAlgorithm(crv))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get verification alg from jwk")
	}
	if err = parsedKey.Set(jwt.IssuerKey, id); err != nil {
		return nil, nil, fmt.Errorf("could not set iss with provided value: %s", kid)
	}
	if err = parsedKey.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, fmt.Errorf("could not set kid with provided value: %s", kid)
	}
	if err = parsedKey.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, nil, fmt.Errorf("could not set alg with value: %s", alg)
	}
	return parsedKey, &alg, nil
}

// GetSigningAlgorithm returns the algorithm used to sign the JWT
func (s *Signer) GetSigningAlgorithm() string {
	return s.Algorithm().String()
}

// SignWithDefaults takes a set of JWT keys and values to add to a JWT before singing them with
// the key defined in the signer. Automatically sets iss and iat
func (s *Signer) SignWithDefaults(kvs map[string]any) ([]byte, error) {
	t := jwt.New()

	// set known default values, which can be overridden by the kvs
	iss := s.ID
	if iss != "" {
		if err := t.Set(jwt.IssuerKey, iss); err != nil {
			return nil, fmt.Errorf("could not set iss with provided value: %s", iss)
		}
	}
	iat := time.Now().Unix()
	if err := t.Set(jwt.IssuedAtKey, iat); err != nil {
		return nil, fmt.Errorf("could not set iat with value: %d", iat)
	}

	for k, v := range kvs {
		if err := t.Set(k, v); err != nil {
			return nil, errors.Wrapf(err, "could not set %s to value: %v", k, v)
		}
	}
	return jwt.Sign(t, jwt.WithKey(s.SignatureAlgorithm, s.Key))
}

// Verify parses a token given the verifier's known algorithm and key, and returns an error, which is nil upon success
func (v *Verifier) Verify(token string) error {
	if _, err := jwt.Parse([]byte(token), jwt.WithKey(v.Algorithm(), v.Key)); err != nil {
		return errors.Wrap(err, "could not verify JWT")
	}
	return nil
}

// Parse attempts to turn a string into a jwt.Token
func (*Verifier) Parse(token string) (jws.Headers, jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not parse JWT")
	}
	headers, err := GetJWSHeaders([]byte(token))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get JWT headers")
	}
	return headers, parsed, nil
}

// VerifyAndParse attempts to turn a string into a jwt.Token and verify its signature using the verifier
func (v *Verifier) VerifyAndParse(token string) (jws.Headers, jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithKey(v.Algorithm(), v.Key))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not parse and verify JWT")
	}
	headers, err := GetJWSHeaders([]byte(token))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get JWT headers")
	}
	return headers, parsed, nil
}

// AlgFromKeyAndCurve returns the supported JSON Web Algorithm for signing for a given key type and curve pair
// The curve parameter is optional (e.g. "") as in the case of RSA.
func AlgFromKeyAndCurve(kty jwa.KeyType, crv jwa.EllipticCurveAlgorithm) (jwa.SignatureAlgorithm, error) {
	if kty == jwa.RSA {
		return jwa.PS256, nil
	}

	if crv == "" {
		return "", errors.New("crv must be specified for non-RSA key types")
	}

	curve := crv
	if kty == jwa.OKP {
		switch curve {
		case jwa.Ed25519:
			return jwa.EdDSA, nil
		default:
			return "", fmt.Errorf("unsupported OKP jwt curve: %s", curve)
		}
	}

	if kty == jwa.EC {
		switch curve {
		case jwa.EllipticCurveAlgorithm(crypto.SECP256k1):
			return jwa.ES256K, nil
		case jwa.P256:
			return jwa.ES256, nil
		case jwa.P384:
			return jwa.ES384, nil
		case jwa.P521:
			return jwa.ES512, nil
		default:
			return "", fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return "", fmt.Errorf("unsupported key type: %s", kty)
}

// IsSupportedJWXSigningVerificationAlgorithm returns true if the algorithm is supported for signing or verifying JWTs
func IsSupportedJWXSigningVerificationAlgorithm(algorithm jwa.SignatureAlgorithm) bool {
	for _, supported := range GetSupportedJWTSigningVerificationAlgorithms() {
		if algorithm == supported {
			return true
		}
	}
	return false
}

// GetSupportedJWTSigningVerificationAlgorithms returns a list of supported signing and verifying algorithms for JWTs
func GetSupportedJWTSigningVerificationAlgorithms() []jwa.SignatureAlgorithm {
	return []jwa.SignatureAlgorithm{
		jwa.PS256,
		jwa.ES256,
		jwa.ES256K,
		jwa.ES384,
		jwa.ES512,
		jwa.EdDSA,
	}
}
