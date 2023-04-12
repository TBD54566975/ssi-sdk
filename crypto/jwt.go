package crypto

import (
	"crypto"
	"fmt"
	"time"

	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
)

// JWTSigner is a struct that contains the key and algorithm used to sign JWTs
type JWTSigner struct {
	ID string
	jwa.SignatureAlgorithm
	jwk.Key
}

func NewJWTSigner(id, kid string, key crypto.PrivateKey) (*JWTSigner, error) {
	privateKeyJWK, err := PrivateKeyToJWK(key)
	if err != nil {
		return nil, err
	}
	return NewJWTSignerFromKey(id, kid, privateKeyJWK)
}

func NewJWTSignerFromJWK(id, kid string, key PrivateKeyJWK) (*JWTSigner, error) {
	gotJWK, alg, err := jwtSigner(id, kid, key)
	if err != nil {
		return nil, err
	}
	if !IsSupportedJWTSigningVerificationAlgorithm(*alg) {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
	return &JWTSigner{
		ID:                 id,
		SignatureAlgorithm: *alg,
		Key:                gotJWK,
	}, nil
}

func NewJWTSignerFromKey(id, kid string, key jwk.Key) (*JWTSigner, error) {
	gotJWK, alg, err := jwtSignerFromKey(id, kid, key)
	if err != nil {
		return nil, err
	}
	if !IsSupportedJWTSigningVerificationAlgorithm(*alg) {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
	return &JWTSigner{ID: id, SignatureAlgorithm: *alg, Key: gotJWK}, nil
}

func (s *JWTSigner) ToVerifier() (*JWTVerifier, error) {
	key, err := s.Key.PublicKey()
	if err != nil {
		return nil, err
	}
	return NewJWTVerifierFromKey(s.ID, key)
}

// JWTVerifier is a struct that contains the key and algorithm used to verify JWTs
type JWTVerifier struct {
	ID string
	jwk.Key
}

func NewJWTVerifier(id string, key crypto.PublicKey) (*JWTVerifier, error) {
	privateKeyJWK, err := PublicKeyToJWK(key)
	if err != nil {
		return nil, err
	}
	return NewJWTVerifierFromKey(id, privateKeyJWK)
}

func NewJWTVerifierFromJWK(id string, key PublicKeyJWK) (*JWTVerifier, error) {
	gotJWK, alg, err := jwtVerifier(id, key)
	if err != nil {
		return nil, err
	}
	if !IsSupportedJWTSigningVerificationAlgorithm(*alg) {
		return nil, fmt.Errorf("unsupported signing/verification algorithm: %s", alg)
	}
	return &JWTVerifier{ID: id, Key: gotJWK}, nil
}

func NewJWTVerifierFromKey(id string, key jwk.Key) (*JWTVerifier, error) {
	gotJWK, alg, err := jwkVerifierFromKey(id, key)
	if err != nil {
		return nil, err
	}
	if !IsSupportedJWTSigningVerificationAlgorithm(*alg) {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}
	return &JWTVerifier{ID: id, Key: gotJWK}, nil
}

func jwtSigner(id, kid string, key PrivateKeyJWK) (jwk.Key, *jwa.SignatureAlgorithm, error) {
	return jwtSignerVerifier(id, kid, key)
}

func jwtSignerFromKey(id, kid string, key jwk.Key) (jwk.Key, *jwa.SignatureAlgorithm, error) {
	return jwtSignerVerifier(id, kid, key)
}

func jwtVerifier(id string, key PublicKeyJWK) (jwk.Key, *jwa.SignatureAlgorithm, error) {
	return jwtSignerVerifier(id, "", key)
}

func jwkVerifierFromKey(id string, key jwk.Key) (jwk.Key, *jwa.SignatureAlgorithm, error) {
	return jwtSignerVerifier(id, "", key)
}

func jwtSignerVerifier(id, kid string, key any) (jwk.Key, *jwa.SignatureAlgorithm, error) {
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
func (s *JWTSigner) GetSigningAlgorithm() string {
	return s.Algorithm().String()
}

// SignWithDefaults takes a set of JWT keys and values to add to a JWT before singing them with
// the key defined in the signer. Automatically sets iss and iat
func (s *JWTSigner) SignWithDefaults(kvs map[string]any) ([]byte, error) {
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

// SignJWS takes a set of payload and signs it with the key defined in the signer
func (s *JWTSigner) SignJWS(payload []byte) ([]byte, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.AlgorithmKey, s.SignatureAlgorithm); err != nil {
		return nil, errors.Wrap(err, "setting algorithm header")
	}
	return jws.Sign(payload, jws.WithKey(s.SignatureAlgorithm, s.Key, jws.WithProtectedHeaders(headers)))
}

// Parse attempts to turn a string into a jwt.Token
func (*JWTSigner) Parse(token string) (jws.Headers, jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not parse JWT")
	}
	headers, err := getJWTHeaders([]byte(token))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get JWT headers")
	}
	return headers, parsed, nil
}

// VerifyJWS parses a token given the verifier's known algorithm and key, and returns an error, which is nil upon success.
func (v *JWTVerifier) VerifyJWS(token string) error {
	key := jws.WithKey(v.Algorithm(), v.Key)
	if _, err := jws.Verify([]byte(token), key); err != nil {
		return errors.Wrap(err, "verifying JWT")
	}
	return nil
}

// Verify parses a token given the verifier's known algorithm and key, and returns an error, which is nil upon success
func (v *JWTVerifier) Verify(token string) error {
	if _, err := jwt.Parse([]byte(token), jwt.WithKey(v.Algorithm(), v.Key)); err != nil {
		return errors.Wrap(err, "could not verify JWT")
	}
	return nil
}

// Parse attempts to turn a string into a jwt.Token
func (*JWTVerifier) Parse(token string) (jws.Headers, jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not parse JWT")
	}
	headers, err := getJWTHeaders([]byte(token))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get JWT headers")
	}
	return headers, parsed, nil
}

// ParseJWS attempts to pull of a single signature from a token, containing its headers
func (*JWTVerifier) ParseJWS(token string) (*jws.Signature, error) {
	parsed, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, errors.Wrap(err, "could not parse JWS")
	}
	signatures := parsed.Signatures()
	if len(signatures) != 1 {
		return nil, fmt.Errorf("expected 1 signature, got %d", len(signatures))
	}
	return signatures[0], nil
}

// VerifyAndParse attempts to turn a string into a jwt.Token and verify its signature using the verifier
func (v *JWTVerifier) VerifyAndParse(token string) (jws.Headers, jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithKey(v.Algorithm(), v.Key))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not parse and verify JWT")
	}
	headers, err := getJWTHeaders([]byte(token))
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not get JWT headers")
	}
	return headers, parsed, nil
}

func GetCRVFromJWK(key jwk.Key) (string, error) {
	maybeCrv, hasCrv := key.Get("crv")
	if hasCrv {
		crv, crvStr := maybeCrv.(jwa.EllipticCurveAlgorithm)
		if !crvStr {
			return "", fmt.Errorf("could not get crv value: %+v", maybeCrv)
		}
		return crv.String(), nil
	}
	return "", nil
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
			return "", fmt.Errorf("unsupported OKP signing curve: %s", curve)
		}
	}

	if kty == jwa.EC {
		switch curve {
		case jwa.EllipticCurveAlgorithm(SECP256k1):
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

// IsSupportedJWTSigningVerificationAlgorithm returns true if the algorithm is supported for signing or verifying JWTs
func IsSupportedJWTSigningVerificationAlgorithm(algorithm jwa.SignatureAlgorithm) bool {
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

func getJWTHeaders(token []byte) (jws.Headers, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return nil, err
	}
	if len(msg.Signatures()) != 1 {
		return nil, fmt.Errorf("expected 1 signature, got %d", len(msg.Signatures()))
	}
	return msg.Signatures()[0].ProtectedHeaders(), nil
}
