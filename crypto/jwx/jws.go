package jwx

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
)

// SignJWS takes a set of payload and signs it with the key defined in the signer
func (s *Signer) SignJWS(payload []byte) ([]byte, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.AlgorithmKey, s.ALG); err != nil {
		return nil, errors.Wrap(err, "setting algorithm header")
	}
	return jws.Sign(payload, jws.WithKey(jwa.SignatureAlgorithm(s.ALG), s.PrivateKey, jws.WithProtectedHeaders(headers)))
}

// Parse attempts to turn a string into a jwt.Token
func (*Signer) Parse(token string) (jws.Headers, jwt.Token, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing JWT")
	}
	headers, err := GetJWSHeaders([]byte(token))
	if err != nil {
		return nil, nil, errors.Wrap(err, "getting JWS headers")
	}
	return headers, parsed, nil
}

// VerifyJWS parses a token given the verifier's known algorithm and key, and returns an error, which is nil upon success.
func (v *Verifier) VerifyJWS(token string) error {
	key := jws.WithKey(jwa.SignatureAlgorithm(v.ALG), v.publicKey)
	if _, err := jws.Verify([]byte(token), key); err != nil {
		return errors.Wrap(err, "verifying JWT")
	}
	return nil
}

// ParseJWS attempts to pull of a single signature from a token, containing its headers
func (*Verifier) ParseJWS(token string) (*jws.Signature, error) {
	parsed, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, errors.Wrap(err, "parsing JWS")
	}
	signatures := parsed.Signatures()
	if len(signatures) != 1 {
		return nil, fmt.Errorf("expected 1 signature, got %d", len(signatures))
	}
	return signatures[0], nil
}

// GetJWSHeaders returns the headers of a JWS signed object, assuming there is only one signature.
func GetJWSHeaders(token []byte) (jws.Headers, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return nil, err
	}
	if len(msg.Signatures()) != 1 {
		return nil, fmt.Errorf("expected 1 signature, got %d", len(msg.Signatures()))
	}
	return msg.Signatures()[0].ProtectedHeaders(), nil
}
