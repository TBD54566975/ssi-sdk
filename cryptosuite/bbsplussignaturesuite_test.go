package cryptosuite

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
)

func TestCVH(t *testing.T) {
	suite := GetBBSPlusSignatureSuite()
	testCred := TestCredential{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/bbs/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       "did:example:123",
		IssuanceDate: "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{
			"id": "did:example:abcd",
		},
	}

	_, priv, err := crypto.GenerateBBSKeyPair()
	assert.NoError(t, err)

	signer, err := NewBBSPlusSigner("test-key-1", priv, Authentication)
	assert.NoError(t, err)
	assert.NotEmpty(t, signer)

	err = suite.Sign(signer, &testCred)
	assert.NoError(t, err)
}
