package credential

import (
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/pkg/errors"
)

const (
	VCMediaType = "application/credential+ld+json"
)

// SignVerifiableCredentialJWS is prepared according to https://transmute-industries.github.io/vc-jws/.
// This is currently an experimental. It's unstable and subject to change. Use at your own peril.
func SignVerifiableCredentialJWS(signer jwx.Signer, cred VerifiableCredential) ([]byte, error) {
	payload, err := json.Marshal(cred)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling credential")
	}

	headers := jws.NewHeaders()
	if err = headers.Set(jws.KeyIDKey, signer.KID); err != nil {
		return nil, errors.Wrap(err, "setting key ID JOSE header")
	}
	if err = headers.Set(jws.ContentTypeKey, VCMediaType); err != nil {
		return nil, errors.Wrap(err, "setting content type JOSE header")
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.SignatureAlgorithm(signer.ALG), signer.PrivateKey, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, errors.Wrap(err, "signing JWT credential")
	}

	return signed, nil
}

// ParseVerifiableCredentialFromJWS parses a JWS. Depending on the `cty` header value, it parses as a JWT or simply
// decodes the payload.
// This is currently an experimental. It's unstable and subject to change. Use at your own peril.
func ParseVerifiableCredentialFromJWS(token string) (*jws.Message, *VerifiableCredential, error) {
	parsed, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, nil, errors.Wrap(err, "parsing JWS")
	}

	var signature *jws.Signature
	for _, s := range parsed.Signatures() {
		if s.ProtectedHeaders().ContentType() == VCMediaType {
			signature = s
		}
	}
	if signature == nil {
		_, _, cred, err := ParseVerifiableCredentialFromJWT(token)
		return parsed, cred, err
	}

	var cred VerifiableCredential
	if err = json.Unmarshal(parsed.Payload(), &cred); err != nil {
		return nil, nil, errors.Wrap(err, "reconstructing Verifiable Credential")
	}

	return parsed, &cred, nil
}

// VerifyVerifiableCredentialJWS verifies the signature validity on the token and parses
// the token in a verifiable credential.
// This is currently an experimental. It's unstable and subject to change. Use at your own peril.
func VerifyVerifiableCredentialJWS(verifier jwx.Verifier, token string) (*jws.Message, *VerifiableCredential, error) {
	if err := verifier.VerifyJWS(token); err != nil {
		return nil, nil, errors.Wrap(err, "verifying JWS")
	}
	return ParseVerifiableCredentialFromJWS(token)
}
