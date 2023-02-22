package cryptosuite

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	bbs "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
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
		CredentialSubject: map[string]interface{}{
			"id": "did:example:abcd",
		},
	}

	key, err := GenerateBLSKey2020()
	assert.NoError(t, err)
	assert.NotEmpty(t, key)

	privKey, err := key.GetPrivateKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, privKey)

	signer := NewBBSPlusSigner("test-key-1", privKey, Authentication)
	assert.NotEmpty(t, signer)

	err = suite.Sign(signer, &testCred)
	assert.NoError(t, err)

	err = suite.Verify(signer, &testCred)
	assert.NoError(t, err)
}

// Case 16: https://github.com/w3c-ccg/vc-api/pull/128/files#diff-df503c1c03bdbbb0eba7241edcad059467116947346f8f89d9b49a064c9f00c3
func TestBBSPlusTestVectors(t *testing.T) {
	// first make sure we can marshal and unmarshal the test vector
	testCred, err := getTestVector(TestVector1)
	assert.NoError(t, err)

	var cred TestCredential
	err = json.Unmarshal([]byte(testCred), &cred)
	assert.NoError(t, err)

	credBytes, err := json.Marshal(cred)
	assert.NoError(t, err)
	assert.JSONEq(t, testCred, string(credBytes))

	// Use the known pk to verify the signature
	suite := GetBBSPlusSignatureSuite()

	// pkBase58 from did:key:zUC724vuGvHpnCGFG1qqpXb81SiBLu3KLSqVzenwEZNPoY35i2Bscb8DLaVwHvRFs6F2NkNNXRcPWvqnPDUd9ukdjLkjZd3u9zzL4wDZDUpkPAatLDGLEYVo8kkAzuAKJQMr7N2
	pubKeyBase58 := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
	pubKeyBytes, err := base58.Decode(pubKeyBase58)
	assert.NoError(t, err)

	pubKey, err := bbs.UnmarshalPublicKey(pubKeyBytes)
	assert.NoError(t, err)
	verifier := crypto.NewBBSPlusVerifier("test-key-1", pubKey)
	err = suite.Verify(verifier, &cred)
	assert.NoError(t, err)
}
