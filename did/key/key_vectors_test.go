package key

import (
	"embed"
	"encoding/json"
	"testing"

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

func TestKnownTestVectors(t *testing.T) {
	tests := []struct {
		name     string
		testFile string
	}{
		{
			name:     "Ed25519/X25519",
			testFile: Ed25519X25519TestVector,
		},
		{
			name:     "X25519",
			testFile: X25519TestVector,
		},
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
			for id, vector := range testVector {
				didKey := DIDKey(id)

				var pubKeyFormatOption Option
				if vector.DIDDocument.VerificationMethod[0].Type == cryptosuite.JSONWebKey2020Type {
					pubKeyFormatOption = PublicKeyFormatJSONWebKey2020
				} else {
					pubKeyFormatOption = PublicKeyFormatMultibase
				}

				var enableEncryptionKeyDerivationOption Option
				if len(vector.DIDDocument.VerificationMethod) < 2 {
					enableEncryptionKeyDerivationOption = DisableEncryptionKeyDerivation
				}
				// note: all other test vectors have this flag set
				if test.name != "Ed25519/X25519" && test.name != "X25519" {
					enableEncryptionKeyDerivationOption = EnableEncryptionKeyDerivation
				}
				didDoc, err := didKey.Expand(pubKeyFormatOption, enableEncryptionKeyDerivationOption)
				assert.NoError(tt, err)
				assert.NotEmpty(tt, didDoc)

				assert.Equal(tt, string(didKey), didDoc.ID)
				assert.Equal(tt, len(vector.DIDDocument.VerificationMethod), len(didDoc.VerificationMethod))
				assert.Equal(tt, vector.DIDDocument.Authentication, didDoc.Authentication)
				assert.Equal(tt, vector.DIDDocument.AssertionMethod, didDoc.AssertionMethod)
				assert.Equal(tt, vector.DIDDocument.KeyAgreement, didDoc.KeyAgreement)
				assert.Equal(tt, vector.DIDDocument.CapabilityInvocation, didDoc.CapabilityInvocation)
				assert.Equal(tt, vector.DIDDocument.CapabilityDelegation, didDoc.CapabilityDelegation)
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
