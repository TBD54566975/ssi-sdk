//go:build jwx_es256k

package signing

import (
	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestVerifiableCredentialJWT(t *testing.T) {
	testCredential := credential.VerifiableCredential{
		Context:           []interface{}{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{},
	}
	signer, key := getTestVectorKey0Signer(t, cryptosuite.AssertionMethod)
	signed, err := SignVerifiableCredentialJWT(signer, testCredential)
	assert.NoError(t, err)

	verifier, err := cryptosuite.NewJSONWebKeyVerifier(key.ID, key.PublicKeyJWK)
	assert.NoError(t, err)

	token := string(signed)
	err = verifier.VerifyJWT(token)
	assert.NoError(t, err)

	parsedCred, err := ParseVerifiableCredentialFromJWT(token)
	assert.NoError(t, err)
	assert.NotEmpty(t, parsedCred)

	cred, err := VerifyVerifiableCredentialJWT(*verifier, token)
	assert.NoError(t, err)
	assert.Equal(t, parsedCred, cred)
}

func TestVerifiablePresentationJWT(t *testing.T) {
	testPresentation := credential.VerifiablePresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		Type:   []string{"VerifiablePresentation"},
		Holder: "did:example:123",
	}
	signer, key := getTestVectorKey0Signer(t, cryptosuite.AssertionMethod)
	signed, err := SignVerifiablePresentationJWT(signer, testPresentation)
	assert.NoError(t, err)

	verifier, err := cryptosuite.NewJSONWebKeyVerifier(key.ID, key.PublicKeyJWK)
	assert.NoError(t, err)

	token := string(signed)
	err = verifier.VerifyJWT(token)
	assert.NoError(t, err)

	parsedPres, err := ParseVerifiablePresentationFromJWT(token)
	assert.NoError(t, err)
	assert.NotEmpty(t, parsedPres)

	pres, err := VerifyVerifiablePresentationJWT(*verifier, token)
	assert.NoError(t, err)
	assert.Equal(t, parsedPres, pres)
}

func getTestVectorKey0Signer(t *testing.T, purpose cryptosuite.ProofPurpose) (cryptosuite.JSONWebKeySigner, cryptosuite.JSONWebKey2020) {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	knownJWK := cryptosuite.JSONWebKey2020{
		ID: "did:example:123#key-0",
		PublicKeyJWK: cryptosuite.PublicKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
		},
		PrivateKeyJWK: cryptosuite.PrivateKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
		},
	}

	signer, err := cryptosuite.NewJSONWebKeySigner(knownJWK.ID, knownJWK.PrivateKeyJWK, purpose)
	assert.NoError(t, err)
	return *signer, knownJWK
}
