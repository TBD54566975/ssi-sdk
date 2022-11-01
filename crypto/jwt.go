package crypto

import (
	"crypto"
	"fmt"
	"time"

	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// JWTSigner is a struct that contains the key and algorithm used to sign JWTs
type JWTSigner struct {
	jwa.SignatureAlgorithm
	jwk.Key
}

func NewJWTSigner(kid string, key crypto.PrivateKey) (*JWTSigner, error) {
	gotJWK, alg, err := jwtSignerVerifier(kid, key)
	if err != nil {
		return nil, err
	}
	return &JWTSigner{
		SignatureAlgorithm: *alg,
		Key:                gotJWK,
	}, nil
}

func (sv *JWTSigner) ToVerifier() (*JWTVerifier, error) {
	key, err := sv.Key.PublicKey()
	if err != nil {
		return nil, err
	}
	return NewJWTVerifier(sv.KeyID(), key)
}

// JWTVerifier is a struct that contains the key and algorithm used to verify JWTs
type JWTVerifier struct {
	jwk.Key
}

func NewJWTVerifier(kid string, key crypto.PublicKey) (*JWTVerifier, error) {
	gotJWK, _, err := jwtSignerVerifier(kid, key)
	if err != nil {
		return nil, err
	}
	return &JWTVerifier{Key: gotJWK}, nil
}

func jwtSignerVerifier(kid string, key interface{}) (jwk.Key, *jwa.SignatureAlgorithm, error) {
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
	// TODO(gabe) distinguish between issuer and kid
	if err = parsedKey.Set(jwt.IssuerKey, kid); err != nil {
		return nil, nil, fmt.Errorf("could not set kid with provided value: %s", kid)
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
func (sv *JWTSigner) GetSigningAlgorithm() string {
	return sv.Algorithm()
}

// SignJWT takes a set of JWT keys and values to add to a JWT before singing them with the key defined in the signer
func (sv *JWTSigner) SignJWT(kvs map[string]interface{}) ([]byte, error) {
	t := jwt.New()

	// set known default values, which can be overridden by the kvs
	kid := sv.Key.KeyID()
	if err := t.Set(jwt.IssuerKey, kid); err != nil {
		return nil, fmt.Errorf("could not set iss with provided value: %s", kid)
	}
	iat := time.Now().Unix()
	if err := t.Set(jwt.IssuedAtKey, iat); err != nil {
		return nil, fmt.Errorf("could not set iat with value: %d", iat)
	}

	for k, v := range kvs {
		if err := t.Set(k, v); err != nil {
			err = errors.Wrapf(err, "could not set %s to value: %v", k, v)
			logrus.WithError(err).Error("could not sign JWT")
			return nil, err
		}
	}
	return jwt.Sign(t, jwa.SignatureAlgorithm(sv.GetSigningAlgorithm()), sv.Key)
}

// ParseJWT attempts to turn a string into a jwt.Token
func (*JWTSigner) ParseJWT(token string) (jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		logrus.WithError(err).Error("could not parse JWT")
		return nil, err
	}
	return parsed, nil
}

// VerifyJWT parses a token given the verifier's known algorithm and key, and returns an error, which is nil upon success
func (sv *JWTVerifier) VerifyJWT(token string) error {
	if _, err := jwt.Parse([]byte(token), jwt.WithVerify(jwa.SignatureAlgorithm(sv.Algorithm()), sv.Key)); err != nil {
		logrus.WithError(err).Error("could not verify JWT")
		return err
	}
	return nil
}

// ParseJWT attempts to turn a string into a jwt.Token
func (*JWTVerifier) ParseJWT(token string) (jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		logrus.WithError(err).Error("could not parse JWT")
		return nil, err
	}
	return parsed, nil
}

// ParseJWS attempts to pull of a single signature from a token, containing its headers
func (*JWTVerifier) ParseJWS(token string) (*jws.Signature, error) {
	parsed, err := jws.Parse([]byte(token))
	if err != nil {
		logrus.WithError(err).Error("could not parse JWS")
		return nil, err
	}
	signatures := parsed.Signatures()
	if len(signatures) != 1 {
		return nil, fmt.Errorf("expected 1 signature, got %d", len(signatures))
	}
	return signatures[0], nil
}

// VerifyAndParseJWT attempts to turn a string into a jwt.Token and verify its signature using the verifier
func (sv *JWTVerifier) VerifyAndParseJWT(token string) (jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithVerify(jwa.SignatureAlgorithm(sv.Algorithm()), sv.Key))
	if err != nil {
		logrus.WithError(err).Error("could not parse and verify JWT")
		return nil, err
	}
	return parsed, nil
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
		default:
			return "", fmt.Errorf("unsupported EC curve: %s", curve)
		}
	}
	return "", fmt.Errorf("unsupported key type: %s", kty)
}
