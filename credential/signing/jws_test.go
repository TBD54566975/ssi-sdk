package signing

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/stretchr/testify/assert"
)

func TestVerifiableCredentialJWS(t *testing.T) {
	testCredential := credential.VerifiableCredential{
		Context:           []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []any{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{},
	}
	signer := getTestVectorKey0Signer(t)

	t.Run("JWT as JWS is parsed correctly", func(t *testing.T) {
		signedJWT, err := SignVerifiableCredentialJWT(signer, testCredential)
		assert.NoError(t, err)

		token := string(signedJWT)
		parsedCred, err := ParseVerifiableCredentialFromJWS(token)
		assert.NoError(t, err)
		assert.Equal(t, &testCredential, parsedCred)
	})

	t.Run("Signing as JWS includes expected protected header", func(t *testing.T) {
		signed, err := SignVerifiableCredentialJWS(signer, testCredential)
		assert.NoError(t, err)

		msg, err := jws.Parse(signed)
		assert.NoError(t, err)
		assert.Len(t, msg.Signatures(), 1)
		assert.Equal(t, "application/credential+ld+json", msg.Signatures()[0].ProtectedHeaders().ContentType())
	})

	t.Run("JWT as JWS can be verified", func(t *testing.T) {
		signed, err := SignVerifiableCredentialJWT(signer, testCredential)
		assert.NoError(t, err)

		verifier, err := signer.ToVerifier()
		assert.NoError(t, err)

		token := string(signed)
		err = verifier.VerifyJWS(token)
		assert.NoError(t, err)
	})

	t.Run("Simple JWS can be verified", func(t *testing.T) {
		signed, err := SignVerifiableCredentialJWS(signer, testCredential)
		assert.NoError(t, err)

		verifier, err := signer.ToVerifier()
		assert.NoError(t, err)

		token := string(signed)
		cred, err := VerifyVerifiableCredentialJWS(*verifier, token)
		assert.NoError(t, err)
		assert.Equal(t, &testCredential, cred)
	})

	t.Run("Parsing JWS returns original credential", func(t *testing.T) {
		signedJWT, err := SignVerifiableCredentialJWS(signer, testCredential)
		assert.NoError(t, err)

		token := string(signedJWT)
		parsedCred, err := ParseVerifiableCredentialFromJWS(token)
		assert.NoError(t, err)
		assert.Equal(t, &testCredential, parsedCred)
	})
}
