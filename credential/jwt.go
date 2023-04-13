package credential

import (
	"context"
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/goccy/go-json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jws"
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
func SignVerifiableCredentialJWT(signer crypto.JWTSigner, cred VerifiableCredential) ([]byte, error) {
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
		return nil, errors.Wrap(err, "jwt JWT credential")
	}
	return signed, nil
}

// VerifyVerifiableCredentialJWT verifies the signature validity on the token and parses
// the token in a verifiable credential.
// TODO(gabe) modify this to add additional verification steps such as credential status, expiration, etc.
// related to https://github.com/TBD54566975/ssi-service/issues/122
func VerifyVerifiableCredentialJWT(verifier crypto.JWTVerifier, token string) (jws.Headers, jwt.Token, *VerifiableCredential, error) {
	if err := verifier.Verify(token); err != nil {
		return nil, nil, nil, errors.Wrap(err, "verifying JWT")
	}
	return ParseVerifiableCredentialFromJWT(token)
}

// ParseVerifiableCredentialFromJWT the JWT is decoded according to the specification.
// https://www.w3.org/TR/vc-data-model/#jwt-decoding
// If there are any issues during decoding, an error is returned. As a result, a successfully
// decoded VerifiableCredential object is returned.
func ParseVerifiableCredentialFromJWT(token string) (jws.Headers, jwt.Token, *VerifiableCredential, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parsing credential token")
	}

	// get headers
	headers, err := GetJWTHeaders([]byte(token))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not get JWT headers")
	}

	// parse remaining JWT properties and set in the credential
	cred, err := ParseVerifiableCredentialFromToken(parsed)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parsing credential from token")
	}

	return headers, parsed, cred, nil
}

// ParseVerifiableCredentialFromToken takes a JWT object and parses it into a VerifiableCredential
func ParseVerifiableCredentialFromToken(token jwt.Token) (*VerifiableCredential, error) {
	// parse remaining JWT properties and set in the credential
	vcClaim, ok := token.Get(VCJWTProperty)
	if !ok {
		return nil, fmt.Errorf("did not find %s property in token", VCJWTProperty)
	}
	vcBytes, err := json.Marshal(vcClaim)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling credential claim")
	}
	var cred VerifiableCredential
	if err = json.Unmarshal(vcBytes, &cred); err != nil {
		return nil, errors.Wrap(err, "reconstructing Verifiable Credential")
	}

	jti, hasJTI := token.Get(jwt.JwtIDKey)
	jtiStr, ok := jti.(string)
	if hasJTI && ok && jtiStr != "" {
		cred.ID = jtiStr
	}

	iat, hasIAT := token.Get(jwt.IssuedAtKey)
	iatTime, ok := iat.(time.Time)
	if hasIAT && ok {
		cred.IssuanceDate = iatTime.Format(time.RFC3339)
	}

	exp, hasExp := token.Get(jwt.ExpirationKey)
	expTime, ok := exp.(time.Time)
	if hasExp && ok {
		cred.ExpirationDate = expTime.Format(time.RFC3339)
	}

	// Note: we only handle string issuer values, not objects for JWTs
	iss, hasIss := token.Get(jwt.IssuerKey)
	issStr, ok := iss.(string)
	if hasIss && ok && issStr != "" {
		cred.Issuer = issStr
	}

	sub, hasSub := token.Get(jwt.SubjectKey)
	subStr, ok := sub.(string)
	if hasSub && ok && subStr != "" {
		if cred.CredentialSubject == nil {
			cred.CredentialSubject = make(map[string]any)
		}
		cred.CredentialSubject[VerifiableCredentialIDProperty] = subStr
	}

	return &cred, nil
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
func SignVerifiablePresentationJWT(signer crypto.JWTSigner, parameters JWTVVPParameters, presentation VerifiablePresentation) ([]byte, error) {
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
		return nil, errors.Wrap(err, "jwt JWT presentation")
	}
	return signed, nil
}

// VerifyVerifiablePresentationJWT verifies the signature validity on the token. Then, the JWT is decoded according
// to the specification: https://www.w3.org/TR/vc-data-model/#jwt-decoding
// After decoding the signature of each credential in the presentation is verified. If there are any issues during
// decoding or signature validation, an error is returned. As a result, a successfully decoded VerifiablePresentation
// object is returned.
func VerifyVerifiablePresentationJWT(verifier crypto.JWTVerifier, resolver did.Resolver, token string) (jws.Headers, jwt.Token, *VerifiablePresentation, error) {
	// verify outer signature on the token
	if err := verifier.Verify(token); err != nil {
		return nil, nil, nil, errors.Wrap(err, "verifying JWT and its signature")
	}

	// parse the token into its parts (header, jwt, vp)
	headers, vpToken, vp, err := ParseVerifiablePresentationFromJWT(token)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parsing VP from JWT")
	}

	// verify signature for each credential in the vp
	for i, cred := range vp.VerifiableCredential {
		// verify the signature on the credential
		// TODO(gabe) generalize this to support other types of credentials and make use of the verification pkg
		// https://github.com/TBD54566975/ssi-sdk/issues/352
		headers, token, cred, err := ToCredential(cred)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "verifying credential[%d] in VP", i)
		}
		if headers == nil || token == nil {
			return nil, nil, nil, errors.Errorf("failed to parse credential[%d] in VP: only JWT VCs supported", i)
		}
		// get key to verify the credential with
		issuerKID := headers.KeyID()
		if issuerKID == "" {
			return nil, nil, nil, errors.Errorf("missing kid in header of credential[%d] in VP", i)
		}
		issuerDID, err := resolver.Resolve(context.Background(), cred.Issuer.(string))
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "resolving issuer DID to verify credential[%d] in VP", i)
		}
		issuerKey, err := did.GetKeyFromVerificationMethod(issuerDID.Document, issuerKID)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "getting key to verify credential[%d] in VP", i)
		}

		// construct a verifier
		credVerifier, err := crypto.NewJWTVerifier(issuerDID.ID, issuerKey)
		if err != nil {
			return nil, nil, nil, errors.Wrapf(err, "constructing verifier for credential[%d] in VP", i)
		}
		// verify the signature
		if err := credVerifier.Verify(token); err != nil {
			return nil, nil, nil, errors.Wrapf(err, "verifying credential[%d] in VP", i)
		}
	}

	// return if successful
	return headers, vpToken, vp, nil
}

// ParseVerifiablePresentationFromJWT the JWT is decoded according to the specification.
// https://www.w3.org/TR/vc-data-model/#jwt-decoding
// If there are any issues during decoding, an error is returned. As a result, a successfully
// decoded VerifiablePresentation object is returned.
func ParseVerifiablePresentationFromJWT(token string) (jws.Headers, jwt.Token, *VerifiablePresentation, error) {
	parsed, err := jwt.Parse([]byte(token), jwt.WithValidate(false), jwt.WithVerify(false))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "parsing vp token")
	}
	vpClaim, ok := parsed.Get(VPJWTProperty)
	if !ok {
		return nil, nil, nil, fmt.Errorf("did not find %s property in token", VPJWTProperty)
	}
	vpBytes, err := json.Marshal(vpClaim)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not marshalling vp claim")
	}
	var pres VerifiablePresentation
	if err = json.Unmarshal(vpBytes, &pres); err != nil {
		return nil, nil, nil, errors.Wrap(err, "reconstructing Verifiable Presentation")
	}

	// get headers
	headers, err := GetJWTHeaders([]byte(token))
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "could not get JWT headers")
	}

	// parse remaining JWT properties and set in the presentation
	iss, ok := parsed.Get(jwt.IssuerKey)
	if !ok {
		return nil, nil, nil, fmt.Errorf("did not find %s property in token", jwt.IssuerKey)
	}
	issStr, ok := iss.(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("issuer property is not a string")
	}
	pres.Holder = issStr

	jti, hasJTI := parsed.Get(jwt.JwtIDKey)
	jtiStr, ok := jti.(string)
	if hasJTI && ok && jtiStr != "" {
		pres.ID = jtiStr
	}

	return headers, parsed, &pres, nil
}

// GetJWTHeaders returns the headers of a JWT token, assuming there is only one signature.
func GetJWTHeaders(token []byte) (jws.Headers, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return nil, err
	}
	if len(msg.Signatures()) != 1 {
		return nil, fmt.Errorf("expected 1 signature, got %d", len(msg.Signatures()))
	}
	return msg.Signatures()[0].ProtectedHeaders(), nil
}
