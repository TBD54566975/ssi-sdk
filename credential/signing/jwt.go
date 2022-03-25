//go:build jwx_es256k

package signing

import (
	"fmt"
	"github.com/TBD54566975/did-sdk/credential"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
	"strconv"
	"time"
)

const (
	VCJWTProperty string = "credential"
	VPJWTProperty string = "vp"
	NonceProperty string = "nonce"
)

// SignVerifiableCredentialJWT is prepared according to https://www.w3.org/TR/vc-data-model/#jwt-encoding
func SignVerifiableCredentialJWT(signer cryptosuite.JSONWebKeySigner, cred credential.VerifiableCredential) ([]byte, error) {
	if cred.IsEmpty() {
		return nil, errors.New("credential cannot be empty")
	}

	t := jwt.New()
	expirationVal := cred.ExpirationDate
	if expirationVal != "" {
		var expirationDate = expirationVal
		if unixTime, err := rfc3339ToUnix(expirationVal); err == nil {
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

	idVal := cred.ID
	if idVal != "" {
		if err := t.Set(jwt.JwtIDKey, idVal); err != nil {
			return nil, errors.Wrap(err, "could not set jti value")
		}
	}

	subVal := cred.CredentialSubject.GetID()
	if subVal != "" {
		if err := t.Set(jwt.SubjectKey, subVal); err != nil {
			return nil, errors.Wrap(err, "could not set subject value")
		}
	}

	if err := t.Set(VCJWTProperty, cred); err != nil {
		return nil, errors.New("could not set credential value")
	}

	return jwt.Sign(t, jwa.SignatureAlgorithm(signer.GetSigningAlgorithm()), signer.Key)
}

// VerifyVerifiableCredentialJWT verifies the signature validity on the token and parses
// the token in a verifiable credential.
func VerifyVerifiableCredentialJWT(verifier cryptosuite.JSONWebKeyVerifier, token string) (*credential.VerifiableCredential, error) {
	if err := verifier.VerifyJWT(token); err != nil {
		return nil, errors.Wrap(err, "could not verify JWT and its signature")
	}
	return ParseVerifiableCredentialFromJWT(token)
}

// ParseVerifiableCredentialFromJWT the JWT is decoded according to the specification.
// https://www.w3.org/TR/vc-data-model/#jwt-decoding
// If there are any issues during decoding, an error is returned. As a result, a successfully
// decoded VerifiableCredential object is returned.
func ParseVerifiableCredentialFromJWT(token string) (*credential.VerifiableCredential, error) {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		return nil, errors.Wrap(err, "could not parse credential token")
	}
	vcClaim, ok := parsed.Get(VCJWTProperty)
	if !ok {
		return nil, fmt.Errorf("did not find %s property in token", VCJWTProperty)
	}
	vcBytes, err := json.Marshal(vcClaim)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal credential claim")
	}
	var cred credential.VerifiableCredential
	if err := json.Unmarshal(vcBytes, &cred); err != nil {
		return nil, errors.Wrap(err, "could not reconstruct Verifiable Credential")
	}

	// parse remaining JWT properties and set in the credential

	exp, hasExp := parsed.Get(jwt.ExpirationKey)
	expStr, ok := exp.(string)
	if hasExp && ok && expStr != "" {
		cred.ExpirationDate = expStr
	}

	// Note: we only handle string issuer values, not objects for JWTs
	iss, hasIss := parsed.Get(jwt.IssuerKey)
	issStr, ok := iss.(string)
	if hasIss && ok && issStr != "" {
		cred.Issuer = issStr
	}

	nbf, hasNbf := parsed.Get(jwt.NotBeforeKey)
	nbfStr, ok := nbf.(string)
	if hasNbf && ok && nbfStr != "" {
		cred.IssuanceDate = nbfStr
	}

	sub, hasSub := parsed.Get(jwt.SubjectKey)
	subStr, ok := sub.(string)
	if hasSub && ok && subStr != "" {
		if cred.CredentialSubject == nil {
			cred.CredentialSubject = make(map[string]interface{})
		}
		cred.CredentialSubject[credential.VerifiableCredentialIDProperty] = subStr
	}

	jti, hasJti := parsed.Get(jwt.NotBeforeKey)
	jtiStr, ok := jti.(string)
	if hasJti && ok && jtiStr != "" {
		cred.ID = jtiStr
	}

	return &cred, nil
}

// SignVerifiablePresentationJWT is prepared according to https://www.w3.org/TR/vc-data-model/#jwt-encoding
func SignVerifiablePresentationJWT(signer cryptosuite.JSONWebKeySigner, pres credential.VerifiablePresentation) ([]byte, error) {
	if pres.IsEmpty() {
		return nil, errors.New("presentation cannot be empty")
	}

	t := jwt.New()
	idVal := pres.ID
	if idVal != "" {
		if err := t.Set(jwt.JwtIDKey, idVal); err != nil {
			return nil, errors.Wrap(err, "could not set jti value")
		}
	}

	subVal := pres.Holder
	if subVal != "" {
		if err := t.Set(jwt.SubjectKey, pres.Holder); err != nil {
			return nil, errors.New("could not set subject value")
		}
	}

	if err := t.Set(VPJWTProperty, pres); err != nil {
		return nil, errors.Wrap(err, "could not set vp value")
	}

	if err := t.Set(NonceProperty, uuid.New().String()); err != nil {
		return nil, errors.Wrap(err, "could not set nonce value")
	}

	return jwt.Sign(t, jwa.SignatureAlgorithm(signer.GetSigningAlgorithm()), signer.Key)
}

// VerifyVerifiablePresentationJWT verifies the signature validity on the token.
// After signature validation, the JWT is decoded according to the specification.
// https://www.w3.org/TR/vc-data-model/#jwt-decoding
// If there are any issues during decoding, an error is returned. As a result, a successfully
// decoded VerifiablePresentation object is returned.
func VerifyVerifiablePresentationJWT(verifier cryptosuite.JSONWebKeyVerifier, token string) (*credential.VerifiablePresentation, error) {
	if err := verifier.VerifyJWT(token); err != nil {
		return nil, errors.Wrap(err, "could not verify JWT and its signature")
	}
	return ParseVerifiablePresentationFromJWT(token)
}

// ParseVerifiablePresentationFromJWT the JWT is decoded according to the specification.
// https://www.w3.org/TR/vc-data-model/#jwt-decoding
// If there are any issues during decoding, an error is returned. As a result, a successfully
// decoded VerifiablePresentation object is returned.
func ParseVerifiablePresentationFromJWT(token string) (*credential.VerifiablePresentation, error) {
	parsed, err := jwt.Parse([]byte(token))
	if err != nil {
		return nil, errors.Wrap(err, "could not parse vp token")
	}
	vpClaim, ok := parsed.Get(VPJWTProperty)
	if !ok {
		return nil, fmt.Errorf("did not find %s property in token", VPJWTProperty)
	}
	vpBytes, err := json.Marshal(vpClaim)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal vp claim")
	}
	var pres credential.VerifiablePresentation
	if err := json.Unmarshal(vpBytes, &pres); err != nil {
		return nil, errors.Wrap(err, "could not reconstruct Verifiable Presentation")
	}

	// parse remaining JWT properties and set in the presentation

	jti, hasJti := parsed.Get(jwt.NotBeforeKey)
	jtiStr, ok := jti.(string)
	if hasJti && ok && jtiStr != "" {
		pres.ID = jtiStr
	}

	return &pres, nil
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
