//go:build jwx_es256k

package cryptosuite

import (
	"github.com/TBD54566975/did-sdk/util"
	"github.com/TBD54566975/did-sdk/vc"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"strconv"
	"time"
)

const (
	VCJWTProperty string = "vc"
	VPJWTProperty string = "vp"
	NonceProperty string = "nonce"
)

// SignVerifiableCredentialJWT is prepared according to https://www.w3.org/TR/vc-data-model/#jwt-encoding
func (s *JSONWebKeySigner) SignVerifiableCredentialJWT(cred vc.VerifiableCredential) ([]byte, error) {
	if cred.IsEmpty() {
		return nil, errors.New("credential cannot be empty")
	}
	t := jwt.New()

	if cred.ExpirationDate != "" {
		var expirationDate = cred.ExpirationDate
		if unixTime, err := rfc3339ToUnix(cred.ExpirationDate); err == nil {
			expirationDate = string(unixTime)
		}
		if err := t.Set(jwt.ExpirationKey, expirationDate); err != nil {
			return nil, errors.Wrap(err, "could not set exp value")
		}
	}
	if err := t.Set(jwt.IssuerKey, cred.Issuer); err != nil {
		return nil, errors.Wrap(err, "could not set exp value")
	}
	var issuanceDate = cred.IssuanceDate
	if unixTime, err := rfc3339ToUnix(cred.IssuanceDate); err == nil {
		issuanceDate = string(unixTime)
	}
	if err := t.Set(jwt.NotBeforeKey, issuanceDate); err != nil {
		return nil, errors.Wrap(err, "could not set nbf value")
	}
	if err := t.Set(jwt.JwtIDKey, cred.ID); err != nil {
		return nil, errors.Wrap(err, "could not set jti value")
	}
	if err := t.Set(jwt.SubjectKey, cred.CredentialSubject.GetID()); err != nil {
		return nil, errors.Wrap(err, "could not set subject value")
	}
	credBytes, err := util.PrettyJSON(cred)
	if err != nil {
		return nil, errors.New("could not marshal cred to JSON")
	}
	credJSON := string(credBytes)
	if err := t.Set(VCJWTProperty, credJSON); err != nil {
		return nil, errors.New("could not set vc value")
	}
	return jwt.Sign(t, jwa.SignatureAlgorithm(s.GetSigningAlgorithm()), s.Key)
}

// VerifyVerifiableCredentialJWT verifies the signature validity on the token.
func (v *JSONWebKeyVerifier) VerifyVerifiableCredentialJWT(token string) error {
	_, err := jwt.Parse([]byte(token), jwt.WithVerify(jwa.SignatureAlgorithm(v.Algorithm()), v.Key))
	return err
}

// VerifiableCredentialFromJWT follows the decoding steps from the spec https://www.w3.org/TR/vc-data-model/#jwt-decoding
func VerifiableCredentialFromJWT(token string) (*vc.VerifiableCredential, error) {
	return nil, nil
}

// SignVerifiablePresentationJWT is prepared according to https://www.w3.org/TR/vc-data-model/#jwt-encoding
func (s *JSONWebKeySigner) SignVerifiablePresentationJWT(pres vc.VerifiablePresentation) ([]byte, error) {
	if pres.IsEmpty() {
		return nil, errors.New("presentation cannot be empty")
	}
	t := jwt.New()
	if err := t.Set(jwt.JwtIDKey, pres.ID); err != nil {
		return nil, errors.Wrap(err, "could not set jti value")
	}
	if err := t.Set(jwt.SubjectKey, pres.Holder); err != nil {
		return nil, errors.New("could not set subject value")
	}
	presBytes, err := util.PrettyJSON(pres)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal cred to JSON")
	}
	presJSON := string(presBytes)
	if err := t.Set(VPJWTProperty, presJSON); err != nil {
		return nil, errors.Wrap(err, "could not set vp value")
	}
	if err := t.Set(NonceProperty, uuid.New().String()); err != nil {
		return nil, errors.Wrap(err, "could not set nonce value")
	}
	return jwt.Sign(t, jwa.SignatureAlgorithm(s.GetSigningAlgorithm()), s.Key)
}

// VerifyVerifiablePresentationJWT verifies the signature validity on the token.
func (v *JSONWebKeyVerifier) VerifyVerifiablePresentationJWT(token string) error {
	_, err := jwt.Parse([]byte(token), jwt.WithVerify(jwa.SignatureAlgorithm(v.Algorithm()), v.Key))
	return err
}

// VerifiablePresentationFromJWT follows the decoding steps from the spec https://www.w3.org/TR/vc-data-model/#jwt-decoding
func VerifiablePresentationFromJWT(token string) (*vc.VerifiablePresentation, error) {
	return nil, nil
}

// according to the spec the JWT timestamp must be a `NumericDate` property, which is a JSON Unix timestamp value.
// https://www.w3.org/TR/vc-data-model/#json-web-token
// https://datatracker.ietf.org/doc/html/rfc7519#section-2
func rfc3339ToUnix(timestamp string) ([]byte, error) {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return nil, err
	}
	unixTimestampInt := strconv.FormatInt(t.Unix(), 10)
	return []byte(unixTimestampInt), nil
}
