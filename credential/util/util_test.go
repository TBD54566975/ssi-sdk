package util

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/stretchr/testify/assert"
)

func TestCredentialsFromInterface(t *testing.T) {
	t.Run("Bad Cred", func(tt *testing.T) {
		parsedCred, err := CredentialsFromInterface("bad")
		assert.Error(tt, err)
		assert.Empty(tt, parsedCred)
	})

	t.Run("Unsigned Cred", func(tt *testing.T) {
		testCred := getTestCredential()

		parsedCred, err := CredentialsFromInterface(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.True(tt, parsedCred.Issuer == testCred.Issuer)
	})

	t.Run("Data Integrity Cred", func(tt *testing.T) {
		knownJWK := cryptosuite.JSONWebKey2020{
			ID: "did:example:123#key-0",
			PublicKeyJWK: crypto.PublicKeyJWK{
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			},
			PrivateKeyJWK: crypto.PrivateKeyJWK{
				KTY: "OKP",
				CRV: "Ed25519",
				X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
				D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
			},
		}

		signer, err := cryptosuite.NewJSONWebKeySigner(knownJWK.ID, knownJWK.PrivateKeyJWK, cryptosuite.AssertionMethod)
		assert.NoError(t, err)

		suite := cryptosuite.GetJSONWebSignature2020Suite()

		testCred := getTestCredential()
		err = suite.Sign(signer, &testCred)
		assert.NoError(t, err)

		parsedCred, err := CredentialsFromInterface(testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.True(tt, parsedCred.Issuer == testCred.Issuer)
	})

	t.Run("JWT Cred", func(tt *testing.T) {
		knownJWK := crypto.PrivateKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
		}

		signer, err := crypto.NewJWTSignerFromJWK(knownJWK.KID, knownJWK)
		assert.NoError(tt, err)

		testCred := getTestCredential()
		signed, err := signing.SignVerifiableCredentialJWT(*signer, testCred)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, signed)

		parsedCred, err := CredentialsFromInterface(string(signed))
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedCred)
		assert.True(tt, parsedCred.Issuer == testCred.Issuer)
	})
}

func getTestCredential() credential.VerifiableCredential {
	return credential.VerifiableCredential{
		Context:           []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{},
	}
}
