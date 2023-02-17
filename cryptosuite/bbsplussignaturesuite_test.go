package cryptosuite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBBSPlusSignatureSuite(t *testing.T) {
	suite := GetBBSPlusSignatureSuite()
	testCred := TestCredential{
		Context: []any{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/bbs/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       "did:example:123",
		IssuanceDate: "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]any{
			"id": "did:example:abcd",
		},
	}

	key, err := GenerateBLSKey2020()
	assert.NoError(t, err)
	assert.NotEmpty(t, key)

	privKey, err := key.GetPrivateKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, privKey)

	signer, err := NewBBSPlusSigner("test-key-1", privKey, Authentication)
	assert.NoError(t, err)
	assert.NotEmpty(t, signer)

	err = suite.Sign(signer, &testCred)
	assert.NoError(t, err)

	verifier, err := signer.ToVerifier()
	assert.NoError(t, err)

	err = suite.Verify(verifier, &testCred)
	assert.NoError(t, err)
}
