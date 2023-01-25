package signing

import (
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

const (
	VCMediaType = "application/credential+ld+json"
)

// SignVerifiableCredentialJWS is prepared according to https://transmute-industries.github.io/vc-jws/.
func SignVerifiableCredentialJWS(signer crypto.JWTSigner, cred credential.VerifiableCredential) ([]byte, error) {
	payload, err := json.Marshal(cred)
	if err != nil {
		return nil, errors.Wrap(err, "marshalling credential")
	}

	hdrs := jws.NewHeaders()
	if err := hdrs.Set(jws.ContentTypeKey, VCMediaType); err != nil {
		return nil, errors.Wrap(err, "setting content type JOSE header")
	}

	signed, err := jws.Sign(payload, jwa.SignatureAlgorithm(signer.GetSigningAlgorithm()), signer.Key, jws.WithHeaders(hdrs))
	if err != nil {
		return nil, errors.Wrap(err, "could not sign JWT credential")
	}

	return signed, nil
}

// ParseVerifiableCredentialFromJWS parses a JWS. Depending on the `cty` header value, it parses as a JWT or simply
// decodes the payload.
func ParseVerifiableCredentialFromJWS(token string) (*credential.VerifiableCredential, error) {
	parsed, err := jws.Parse([]byte(token))
	if err != nil {
		return nil, errors.Wrap(err, "parsing token")
	}

	var signature *jws.Signature
	for _, s := range parsed.Signatures() {
		if s.ProtectedHeaders().ContentType() == VCMediaType {
			signature = s
		}
	}
	if signature == nil {
		return ParseVerifiableCredentialFromJWT(token)
	}

	var cred credential.VerifiableCredential
	if err = json.Unmarshal(parsed.Payload(), &cred); err != nil {
		return nil, errors.Wrap(err, "could not reconstruct Verifiable Credential")
	}

	return &cred, nil
}

// VerifyVerifiableCredentialJWS verifies the signature validity on the token and parses
// the token in a verifiable credential.
func VerifyVerifiableCredentialJWS(verifier crypto.JWTVerifier, token string) (*credential.VerifiableCredential, error) {
	if err := verifier.VerifyJWS(token); err != nil {
		return nil, errors.Wrap(err, "could not verify JWT and its signature")
	}
	return ParseVerifiableCredentialFromJWS(token)
}
