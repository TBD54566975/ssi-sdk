package credential

import (
	"context"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

func TestVerifiableCredentialJWS(t *testing.T) {
	testCredential := VerifiableCredential{
		Context:           []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []any{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{},
	}
	signer := getTestVectorKey0Signer(t)

	t.Run("JWT as JWS is parsed correctly", func(tt *testing.T) {
		signedJWT, err := SignVerifiableCredentialJWT(signer, testCredential)
		assert.NoError(tt, err)

		parsed, err := jwt.Parse(signedJWT, jwt.WithVerify(false))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsed)
		tokenMap, err := parsed.AsMap(context.Background())
		assert.NoError(tt, err)
		assert.NotEmpty(tt, tokenMap)
		vcClaims, ok := tokenMap["vc"].(map[string]interface{})
		assert.True(tt, ok)
		assert.NotEmpty(tt, vcClaims)
		assert.NotContains(tt, vcClaims, "issuanceDate")

		token := string(signedJWT)
		jws, parsedCred, err := ParseVerifiableCredentialFromJWS(token)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jws)
		assert.Equal(tt, &testCredential, parsedCred)
	})

	t.Run("Signing as JWS includes expected protected header", func(tt *testing.T) {
		signed, err := SignVerifiableCredentialJWS(signer, testCredential)
		assert.NoError(tt, err)

		msg, err := jws.Parse(signed)
		assert.NoError(tt, err)
		assert.Len(tt, msg.Signatures(), 1)
		assert.Equal(tt, "application/credential+ld+json", msg.Signatures()[0].ProtectedHeaders().ContentType())
	})

	t.Run("JWT as JWS can be verified", func(tt *testing.T) {
		signed, err := SignVerifiableCredentialJWT(signer, testCredential)
		assert.NoError(tt, err)

		verifier, err := signer.ToVerifier(signer.ID)
		assert.NoError(tt, err)

		token := string(signed)
		err = verifier.VerifyJWS(token)
		assert.NoError(tt, err)
	})

	t.Run("Simple JWS can be verified", func(tt *testing.T) {
		signed, err := SignVerifiableCredentialJWS(signer, testCredential)
		assert.NoError(tt, err)

		verifier, err := signer.ToVerifier(signer.ID)
		assert.NoError(tt, err)

		token := string(signed)
		jws, cred, err := VerifyVerifiableCredentialJWS(*verifier, token)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jws)
		assert.Equal(tt, &testCredential, cred)
	})

	t.Run("Parsing JWS returns original credential", func(tt *testing.T) {
		signedJWT, err := SignVerifiableCredentialJWS(signer, testCredential)
		assert.NoError(tt, err)

		token := string(signedJWT)
		jws, parsedCred, err := ParseVerifiableCredentialFromJWS(token)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, jws)
		assert.Equal(tt, &testCredential, parsedCred)
	})
}
