//go:build jwx_es256k

package cryptosuite

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// SignGenericJWT takes a set of JWT keys and values to add to a JWT
func (s *JSONWebKeySigner) SignGenericJWT(kvs map[string]interface{}) ([]byte, error) {
	t := jwt.New()
	for k, v := range kvs {
		if err := t.Set(k, v); err != nil {
			err := errors.Wrapf(err, "could not set %s to value: %v", k, v)
			logrus.WithError(err).Error("could not sign JWT")
			return nil, err
		}
	}
	return jwt.Sign(t, jwa.SignatureAlgorithm(s.GetSigningAlgorithm()), s.Key)
}

// ParseJWT attempts to turn a string into a jwt.Token
func (s *JSONWebKeySigner) ParseJWT(token string) (jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		logrus.WithError(err).Error("could not parse JWT")
		return nil, err
	}
	return parsed, nil
}

// VerifyJWT parses a token given the verifier's known algorithm and key, and returns an error, which is nil upon success
func (v *JSONWebKeyVerifier) VerifyJWT(token string) error {
	if _, err := jwt.Parse([]byte(token), jwt.WithVerify(jwa.SignatureAlgorithm(v.Algorithm()), v.Key)); err != nil {
		logrus.WithError(err).Error("could not verify JWT")
		return err
	}
	return nil
}

// ParseJWT attempts to turn a string into a jwt.Token
func (v *JSONWebKeyVerifier) ParseJWT(token string) (jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		logrus.WithError(err).Error("could not parse JWT")
		return nil, err
	}
	return parsed, nil
}

// VerifyAndParseJWT attempts to turn a string into a jwt.Token and verify its signature using the verifier
func (v *JSONWebKeyVerifier) VerifyAndParseJWT(token string) (jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithVerify(jwa.SignatureAlgorithm(v.Algorithm()), v.Key))
	if err != nil {
		logrus.WithError(err).Error("could not parse and verify JWT")
		return nil, err
	}
	return parsed, nil
}
