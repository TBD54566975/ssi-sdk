package cryptosuite

import (
	"errors"
	"github.com/TBD54566975/did-sdk/util"
	"github.com/TBD54566975/did-sdk/vc"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
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
	if err := t.Set(jwt.ExpirationKey, cred.ExpirationDate); err != nil {
		return nil, errors.New("could not set exp value")
	}
	if err := t.Set(jwt.IssuerKey, cred.Issuer); err != nil {
		return nil, errors.New("could not set exp value")
	}
	if err := t.Set(jwt.NotBeforeKey, cred.IssuanceDate); err != nil {
		return nil, errors.New("could not set nbf value")
	}
	if err := t.Set(jwt.JwtIDKey, cred.ID); err != nil {
		return nil, errors.New("could not set jti value")
	}
	if err := t.Set(jwt.SubjectKey, cred.CredentialSubject.GetID()); err != nil {
		return nil, errors.New("could not set subject value")
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

func (v *JSONWebKeyVerifier) VerifyVerifiableCredentialJWT(token jwt.Token) error {
	return nil
}

// SignVerifiablePresentationJWT is prepared according to https://www.w3.org/TR/vc-data-model/#jwt-encoding
func (s *JSONWebKeySigner) SignVerifiablePresentationJWT(pres vc.VerifiablePresentation) ([]byte, error) {
	if pres.IsEmpty() {
		return nil, errors.New("presentation cannot be empty")
	}
	t := jwt.New()
	if err := t.Set(jwt.JwtIDKey, pres.ID); err != nil {
		return nil, errors.New("could not set jti value")
	}
	if err := t.Set(jwt.SubjectKey, pres.Holder); err != nil {
		return nil, errors.New("could not set subject value")
	}
	presBytes, err := util.PrettyJSON(pres)
	if err != nil {
		return nil, errors.New("could not marshal cred to JSON")
	}
	presJSON := string(presBytes)
	if err := t.Set(VPJWTProperty, presJSON); err != nil {
		return nil, errors.New("could not set vp value")
	}
	if err := t.Set(NonceProperty, uuid.New().String()); err != nil {
		return nil, errors.New("could not set nonce value")
	}
	return jwt.Sign(t, jwa.SignatureAlgorithm(s.GetSigningAlgorithm()), s.Key)
}

func (v *JSONWebKeyVerifier) VerifyVerifiablePresentationJWT() error {
	return nil
}
