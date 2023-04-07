package signing

import (
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
)

const (
	VCJWTProperty string = "vc"
	VPJWTProperty string = "vp"
	NonceProperty string = "nonce"
)

// SignVerifiableCredentialJWT is prepared according to https://w3c.github.io/vc-jwt/#version-1.1
// which will soon be deprecated by https://w3c.github.io/vc-jwt/ see: https://github.com/TBD54566975/ssi-sdk/issues/191
func SignVerifiableCredentialJWT(signer crypto.JWTSigner, cred credential.VerifiableCredential) ([]byte, error) {
	if cred.IsEmpty() {
		return nil, errors.New("credential cannot be empty")
	}
	if cred.Proof != nil {
		return nil, errors.New("credential cannot already have a proof")
	}

	t := jwt.New()
	if cred.ExpirationDate != "" {
		if err := t.Set(jwt.ExpirationKey, cred.ExpirationDate); err != nil {
			return nil, errors.Wrap(err, "could not set exp value")
		}

		// remove the expiration date from the credential
		cred.ExpirationDate = ""
	}

	if err := t.Set(NonceProperty, uuid.New().String()); err != nil {
		return nil, errors.Wrap(err, "setting nonce value")
	}

	if err := t.Set(jwt.IssuerKey, cred.Issuer); err != nil {
		return nil, errors.Wrap(err, "could not set exp value")
	}
	// remove the issuer from the credential
	cred.Issuer = ""

	if err := t.Set(jwt.IssuedAtKey, cred.IssuanceDate); err != nil {
		return nil, errors.Wrap(err, "could not set iat value")
	}
	if err := t.Set(jwt.NotBeforeKey, cred.IssuanceDate); err != nil {
		return nil, errors.Wrap(err, "could not set nbf value")
	}
	// remove the issuance date from the credential
	cred.IssuanceDate = ""

	idVal := cred.ID
	if idVal != "" {
		if err := t.Set(jwt.JwtIDKey, idVal); err != nil {
			return nil, errors.Wrap(err, "could not set jti value")
		}
		// remove the id from the credential
		cred.ID = ""
	}

	subVal := cred.CredentialSubject.GetID()
	if subVal != "" {
		if err := t.Set(jwt.SubjectKey, subVal); err != nil {
			return nil, errors.Wrap(err, "setting subject value")
		}
		// remove the id from the credential subject
		delete(cred.CredentialSubject, "id")
	}

	if err := t.Set(VCJWTProperty, cred); err != nil {
		return nil, errors.New("setting credential value")
	}

	signed, err := jwt.Sign(t, jwt.WithKey(signer.SignatureAlgorithm, signer.Key))
	if err != nil {
		return nil, errors.Wrap(err, "signing JWT credential")
	}
	return signed, nil
}

// VerifyVerifiableCredentialJWT verifies the signature validity on the token and parses
// the token in a verifiable credential.
func VerifyVerifiableCredentialJWT(verifier crypto.JWTVerifier, token string) (jwt.Token, *credential.VerifiableCredential, error) {
	if err := verifier.Verify(token); err != nil {
		return nil, nil, errors.Wrap(err, "verifying JWT")
	}
	return ParseVerifiableCredentialFromJWT(token)
}

// ParseVerifiableCredentialFromJWT the JWT is decoded according to the specification.
// https://www.w3.org/TR/vc-data-model/#jwt-decoding
// If there are any issues during decoding, an error is returned. As a result, a successfully
// decoded VerifiableCredential object is returned.
func ParseVerifiableCredentialFromJWT(token string) (jwt.Token, *credential.VerifiableCredential, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing credential token")
	}
	vcClaim, ok := parsed.Get(VCJWTProperty)
	if !ok {
		return nil, nil, fmt.Errorf("did not find %s property in token", VCJWTProperty)
	}
	vcBytes, err := json.Marshal(vcClaim)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshalling credential claim")
	}
	var cred credential.VerifiableCredential
	if err = json.Unmarshal(vcBytes, &cred); err != nil {
		return nil, nil, errors.Wrap(err, "reconstructing Verifiable Credential")
	}

	// parse remaining JWT properties and set in the credential
	jti, hasJTI := parsed.Get(jwt.JwtIDKey)
	jtiStr, ok := jti.(string)
	if hasJTI && ok && jtiStr != "" {
		cred.ID = jtiStr
	}

	iat, hasIAT := parsed.Get(jwt.IssuedAtKey)
	iatTime, ok := iat.(time.Time)
	if hasIAT && ok {
		cred.IssuanceDate = iatTime.Format(time.RFC3339)
	}

	exp, hasExp := parsed.Get(jwt.ExpirationKey)
	expTime, ok := exp.(time.Time)
	if hasExp && ok {
		cred.ExpirationDate = expTime.Format(time.RFC3339)
	}

	// Note: we only handle string issuer values, not objects for JWTs
	iss, hasIss := parsed.Get(jwt.IssuerKey)
	issStr, ok := iss.(string)
	if hasIss && ok && issStr != "" {
		cred.Issuer = issStr
	}

	sub, hasSub := parsed.Get(jwt.SubjectKey)
	subStr, ok := sub.(string)
	if hasSub && ok && subStr != "" {
		if cred.CredentialSubject == nil {
			cred.CredentialSubject = make(map[string]any)
		}
		cred.CredentialSubject[credential.VerifiableCredentialIDProperty] = subStr
	}

	return parsed, &cred, nil
}

// JWTVVPParameters represents additional parameters needed when constructing a JWT VP as opposed to a VP
type JWTVVPParameters struct {
	// Audience is a required intended audience of the JWT.
	Audience string `validate:"required"`
	// Expiration is an optional expiration time of the JWT using the `exp` property.
	Expiration int
}

// SignVerifiablePresentationJWT transforms a VP into a VP JWT and signs it
// According to https://w3c.github.io/vc-jwt/#version-1.1
func SignVerifiablePresentationJWT(signer crypto.JWTSigner, parameters JWTVVPParameters, presentation credential.VerifiablePresentation) ([]byte, error) {
	if parameters.Audience == "" {
		return nil, errors.New("audience cannot be empty")
	}
	if presentation.IsEmpty() {
		return nil, errors.New("presentation cannot be empty")
	}
	if presentation.Proof != nil {
		return nil, errors.New("presentation cannot have a proof")
	}

	t := jwt.New()
	// set JWT-VP specific parameters
	if err := t.Set(jwt.AudienceKey, parameters.Audience); err != nil {
		return nil, errors.Wrap(err, "setting audience value")
	}
	iatAndNBF := time.Now().Unix()
	if err := t.Set(jwt.IssuedAtKey, iatAndNBF); err != nil {
		return nil, errors.Wrap(err, "setting iat value")
	}
	if err := t.Set(jwt.NotBeforeKey, iatAndNBF); err != nil {
		return nil, errors.Wrap(err, "setting nbf value")
	}

	if err := t.Set(NonceProperty, uuid.New().String()); err != nil {
		return nil, errors.Wrap(err, "setting nonce value")
	}

	if parameters.Expiration > 0 {
		if err := t.Set(jwt.ExpirationKey, parameters.Expiration); err != nil {
			return nil, errors.Wrap(err, "setting exp value")
		}
	}

	// map the VP properties to JWT properties, and remove from the VP
	if presentation.ID != "" {
		if err := t.Set(jwt.JwtIDKey, presentation.ID); err != nil {
			return nil, errors.Wrap(err, "setting jti value")
		}
		// remove from VP
		presentation.ID = ""
	}
	if presentation.Holder != "" {
		if err := t.Set(jwt.IssuerKey, presentation.Holder); err != nil {
			return nil, errors.New("setting subject value")
		}
		// remove from VP
		presentation.Holder = ""
	}

	if err := t.Set(VPJWTProperty, presentation); err != nil {
		return nil, errors.Wrap(err, "setting vp value")
	}

	signed, err := jwt.Sign(t, jwt.WithKey(signer.SignatureAlgorithm, signer.Key))
	if err != nil {
		return nil, errors.Wrap(err, "signing JWT presentation")
	}
	return signed, nil
}

// VerifyVerifiablePresentationJWT verifies the signature validity on the token.
// After signature validation, the JWT is decoded according to the specification.
// https://www.w3.org/TR/vc-data-model/#jwt-decoding
// If there are any issues during decoding, an error is returned. As a result, a successfully
// decoded VerifiablePresentation object is returned.
func VerifyVerifiablePresentationJWT(verifier crypto.JWTVerifier, token string) (jwt.Token, *credential.VerifiablePresentation, error) {
	if err := verifier.Verify(token); err != nil {
		return nil, nil, errors.Wrap(err, "verifying JWT and its signature")
	}
	return ParseVerifiablePresentationFromJWT(token)
}

// ParseVerifiablePresentationFromJWT the JWT is decoded according to the specification.
// https://www.w3.org/TR/vc-data-model/#jwt-decoding
// If there are any issues during decoding, an error is returned. As a result, a successfully
// decoded VerifiablePresentation object is returned.
func ParseVerifiablePresentationFromJWT(token string) (jwt.Token, *credential.VerifiablePresentation, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing vp token")
	}
	vpClaim, ok := parsed.Get(VPJWTProperty)
	if !ok {
		return nil, nil, fmt.Errorf("did not find %s property in token", VPJWTProperty)
	}
	vpBytes, err := json.Marshal(vpClaim)
	if err != nil {
		return nil, nil, errors.Wrap(err, "could not marshalling vp claim")
	}
	var pres credential.VerifiablePresentation
	if err = json.Unmarshal(vpBytes, &pres); err != nil {
		return nil, nil, errors.Wrap(err, "reconstructing Verifiable Presentation")
	}

	// parse remaining JWT properties and set in the presentation
	iss, ok := parsed.Get(jwt.IssuerKey)
	if !ok {
		return nil, nil, fmt.Errorf("did not find %s property in token", jwt.IssuerKey)
	}
	issStr, ok := iss.(string)
	if !ok {
		return nil, nil, fmt.Errorf("issuer property is not a string")
	}
	pres.Holder = issStr

	jti, hasJTI := parsed.Get(jwt.JwtIDKey)
	jtiStr, ok := jti.(string)
	if hasJTI && ok && jtiStr != "" {
		pres.ID = jtiStr
	}

	return parsed, &pres, nil
}
