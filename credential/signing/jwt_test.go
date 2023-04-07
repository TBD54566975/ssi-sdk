//go:build jwx_es256k

package signing

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/credential"
)

func TestVerifiableCredentialJWT(t *testing.T) {
	testCredential := credential.VerifiableCredential{
		Context:           []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{},
	}

	t.Run("Known JWK Signer", func(t *testing.T) {
		signer := getTestVectorKey0Signer(t)
		signed, err := SignVerifiableCredentialJWT(signer, testCredential)
		assert.NoError(t, err)

		verifier, err := signer.ToVerifier()
		assert.NoError(t, err)

		token := string(signed)
		err = verifier.Verify(token)
		assert.NoError(t, err)

		parsedJWT, parsedCred, err := ParseVerifiableCredentialFromJWT(token)
		assert.NoError(t, err)
		assert.NotEmpty(t, parsedJWT)
		assert.NotEmpty(t, parsedCred)

		verifiedJWT, cred, err := VerifyVerifiableCredentialJWT(*verifier, token)
		assert.NoError(t, err)
		assert.NotEmpty(t, verifiedJWT)
		assert.Equal(t, parsedJWT, verifiedJWT)
		assert.Equal(t, parsedCred, cred)
	})

	t.Run("Generated Private Key For Signer", func(tt *testing.T) {
		_, privKey, err := crypto.GenerateEd25519Key()
		assert.NoError(tt, err)

		signer, err := crypto.NewJWTSigner("test-id", "test-kid", privKey)
		assert.NoError(tt, err)

		signed, err := SignVerifiableCredentialJWT(*signer, testCredential)
		assert.NoError(tt, err)

		verifier, err := signer.ToVerifier()
		assert.NoError(tt, err)

		token := string(signed)
		err = verifier.Verify(token)
		assert.NoError(tt, err)

		parsedJWT, parsedCred, err := ParseVerifiableCredentialFromJWT(token)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, parsedJWT)
		assert.NotEmpty(tt, parsedCred)

		verifiedJWT, cred, err := VerifyVerifiableCredentialJWT(*verifier, token)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, verifiedJWT)
		assert.Equal(tt, parsedJWT, verifiedJWT)
		assert.Equal(tt, parsedCred, cred)
	})
}

func TestVerifiablePresentationJWT(t *testing.T) {
	testPresentation := credential.VerifiablePresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		Type:   []string{"VerifiablePresentation"},
		Holder: "did:example:123",
	}

	signer := getTestVectorKey0Signer(t)
	signed, err := SignVerifiablePresentationJWT(signer, JWTVVPParameters{Audience: "did:test:aud"}, testPresentation)
	assert.NoError(t, err)

	verifier, err := signer.ToVerifier()
	assert.NoError(t, err)

	token := string(signed)
	err = verifier.Verify(token)
	assert.NoError(t, err)

	parsedJWT, parsedPres, err := ParseVerifiablePresentationFromJWT(token)
	assert.NoError(t, err)
	assert.NotEmpty(t, parsedJWT)
	assert.NotEmpty(t, parsedPres)

	verifiedJWT, pres, err := VerifyVerifiablePresentationJWT(*verifier, token)
	assert.NoError(t, err)
	assert.NotEmpty(t, verifiedJWT)
	assert.Equal(t, parsedPres, pres)
}

func getTestVectorKey0Signer(t *testing.T) crypto.JWTSigner {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	knownJWK := crypto.PrivateKeyJWK{
		KTY: "OKP",
		CRV: "Ed25519",
		X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
		D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
	}

	signer, err := crypto.NewJWTSignerFromJWK("signer-id", knownJWK.KID, knownJWK)
	assert.NoError(t, err)
	return *signer
}
