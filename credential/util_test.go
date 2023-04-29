package credential

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/stretchr/testify/assert"
)

func TestCredentialsFromInterface(t *testing.T) {
	t.Run("Bad Cred", func(tt *testing.T) {
		_, _, parsedCred, err := ToCredential("bad")
		assert.Error(tt, err)
		assert.Empty(tt, parsedCred)

		genericCred, err := ToCredentialJSONMap("bad")
		assert.Error(tt, err)
		assert.Empty(tt, genericCred)
	})

	t.Run("Unsigned Cred", func(tt *testing.T) {
		testCred := getTestCredential()

		_, _, parsedCred, err := ToCredential(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.Equal(tt, testCred.Issuer, parsedCred.Issuer)

		genericCred, err := ToCredentialJSONMap(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, genericCred)
		assert.Equal(tt, testCred.Issuer, genericCred["issuer"])
	})

	t.Run("Data Integrity Cred", func(tt *testing.T) {
		knownJWK := cryptosuite.JSONWebKey2020{
			ID: "did:example:123#key-0",
			PublicKeyJWK: jwx.PublicKeyJWK{
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			},
			PrivateKeyJWK: jwx.PrivateKeyJWK{
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
				D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
			},
		}

		signer, err := cryptosuite.NewJSONWebKeySigner("issuer-id", knownJWK.ID, knownJWK.PrivateKeyJWK, cryptosuite.AssertionMethod)
		assert.NoError(t, err)

		suite := cryptosuite.GetJSONWebSignature2020Suite()

		testCred := getTestCredential()
		err = suite.Sign(signer, &testCred)
		assert.NoError(t, err)

		_, _, parsedCred, err := ToCredential(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.Equal(tt, testCred.Issuer, parsedCred.Issuer)

		genericCred, err := ToCredentialJSONMap(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, genericCred)
		assert.Equal(tt, parsedCred.Issuer, genericCred["issuer"])
	})

	t.Run("JWT Cred", func(tt *testing.T) {
		knownJWK := jwx.PrivateKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
		}

		signer, err := jwx.NewJWXSignerFromJWK("signer-id", knownJWK.KID, knownJWK)
		assert.NoError(tt, err)

		testCred := getTestCredential()
		signed, err := SignVerifiableCredentialJWT(*signer, testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signed)

		headers, token, parsedCred, err := ToCredential(string(signed))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.NotEmpty(tt, headers)
		assert.NotEmpty(tt, token)
		assert.Equal(tt, parsedCred.Issuer, testCred.Issuer)
		gotIss, ok := token.Get("iss")
		assert.True(tt, ok)
		assert.Equal(tt, gotIss.(string), testCred.Issuer)

		genericCred, err := ToCredentialJSONMap(string(signed))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, genericCred)
		assert.Equal(tt, parsedCred.Issuer, genericCred["iss"])
	})
}

func getTestCredential() VerifiableCredential {
	return VerifiableCredential{
		Context:           []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{},
	}
}
