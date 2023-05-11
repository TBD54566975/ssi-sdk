package key

import (
	"embed"
	"encoding/json"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed testdata
	testData embed.FS
)

const (
	Ed25519X25519TestVector string = "ed25519-x25519.json"
	X25519TestVector        string = "x25519.json"
	NISTCurvesTestVector    string = "nist-curves.json"
	RSATestVector           string = "rsa.json"
	SECP256k1TestVector     string = "secp256k1.json"
)

func TestJWK(t *testing.T) {
	pk := jwx.PublicKeyJWK{
		KTY: "EC",
		CRV: "P-256",
		X:   "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
		Y:   "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM",
	}
	pubKey, err := pk.ToPublicKey()
	assert.NoError(t, err)
	assert.NotEmpty(t, pubKey)

	pkBytes, err := crypto.PubKeyToBytes(pubKey)
	assert.NoError(t, err)

	didKey, err := CreateDIDKey(crypto.P256, pkBytes)
	assert.NoError(t, err)
	assert.NotEmpty(t, didKey)

	didDoc, err := didKey.Expand()
	assert.NoError(t, err)
	assert.NotEmpty(t, didDoc)

	didDocBytes, err := json.Marshal(didDoc)
	assert.NoError(t, err)
	assert.NotEmpty(t, didDocBytes)
	println(string(didDocBytes))
}

func TestKnownTestVectors(t *testing.T) {
	tests := []struct {
		name     string
		testFile string
	}{
		// {
		// 	name:     "Ed25519/X25519",
		// 	testFile: Ed25519X25519TestVector,
		// },
		// {
		// 	name:     "X25519",
		// 	testFile: X25519TestVector,
		// },
		{
			name:     "NIST Curves",
			testFile: NISTCurvesTestVector,
		},
		{
			name:     "RSA",
			testFile: RSATestVector,
		},
		{
			name:     "secp256k1",
			testFile: SECP256k1TestVector,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			testVector := retrieveTestVector(tt, test.testFile)
			limit := 0
			for id, vector := range testVector {
				// if limit > 0 {
				// 	break
				// }

				didKey := DIDKey(id)

				var pubKeyFormatOption Option
				if vector.DIDDocument.VerificationMethod[0].Type == cryptosuite.JSONWebKey2020Type {
					pubKeyFormatOption = PublicKeyFormatJSONWebKey2020
				} else {
					pubKeyFormatOption = PublicKeyFormatMultibase
				}
				didDoc, err := didKey.Expand(pubKeyFormatOption)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, didDoc)

				assert.Equal(tt, string(didKey), didDoc.ID)
				assert.Equal(tt, len(didDoc.VerificationMethod), len(vector.DIDDocument.VerificationMethod))
				assert.Equal(tt, didDoc.Authentication, vector.DIDDocument.Authentication)
				assert.Equal(tt, didDoc.AssertionMethod, vector.DIDDocument.AssertionMethod)
				assert.Equal(tt, didDoc.KeyAgreement, vector.DIDDocument.KeyAgreement)
				assert.Equal(tt, didDoc.CapabilityInvocation, vector.DIDDocument.CapabilityInvocation)
				assert.Equal(tt, didDoc.CapabilityDelegation, vector.DIDDocument.CapabilityDelegation)

				ourDIDBytes, err := json.Marshal(didDoc)
				assert.NoError(tt, err)
				limit++
				println(string(ourDIDBytes))
			}
		})
	}
}

// From https://w3c-ccg.github.io/did-method-key/#test-vectors

type didKeyTestVector struct {
	Seed                string                 `json:"seed,omitempty"`
	VerificationKeyPair did.VerificationMethod `json:"verificationKeyPair,omitempty"`
	KeyAgreementKeyPair did.VerificationMethod `json:"keyAgreementKeyPair,omitempty"`
	DIDDocument         did.Document           `json:"didDocument,omitempty"`
}

func getTestData(fileName string) ([]byte, error) {
	return testData.ReadFile("testdata/" + fileName)
}

// retrieveTestVectorAs retrieves a test vector from the testdata folder and unmarshals it into the given interface
func retrieveTestVector(t *testing.T, fileName string) map[string]didKeyTestVector {
	t.Helper()
	testDataBytes, err := getTestData(fileName)
	require.NoError(t, err)
	output := make(map[string]didKeyTestVector)
	err = json.Unmarshal(testDataBytes, &output)
	require.NoError(t, err)
	return output
}
