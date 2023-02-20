package cryptosuite

import (
	"encoding/base64"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	bbs "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	VCTestVector string = "vc_test_vector.jsonld"
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

func TestBBSPlusTestVectors(t *testing.T) {
	// first make sure we can marshal and unmarshal the test vector
	testCred, err := getTestVector(VCTestVector)
	assert.NoError(t, err)

	var cred TestCredential
	err = json.Unmarshal([]byte(testCred), &cred)
	assert.NoError(t, err)

	credBytes, err := json.Marshal(cred)
	assert.NoError(t, err)
	assert.JSONEq(t, testCred, string(credBytes))

	// Use the known pk to verify the signature
	suite := GetBBSPlusSignatureSuite()

	pkBase64 := "h/rkcTKXXzRbOPr9UxSfegCbid2U/cVNXQUaKeGF7UhwrMJFP70uMH0VQ9+3+/2zDPAAjflsdeLkOXW3+ShktLxuPy8UlXSNgKNmkfb+rrj+FRwbs13pv/WsIf+eV66+"
	pkBytes, err := base64.RawStdEncoding.DecodeString(pkBase64)
	require.NoError(t, err)

	pubKey, err := bbs.UnmarshalPublicKey(pkBytes)
	assert.NoError(t, err)
	verifier, err := crypto.NewBBSPlusVerifier("test-key-1", pubKey)
	assert.NoError(t, err)

	err = suite.Verify(verifier, &cred)
	assert.NoError(t, err)
}
