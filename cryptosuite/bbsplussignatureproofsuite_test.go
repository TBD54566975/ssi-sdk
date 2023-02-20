package cryptosuite

import (
	"embed"
	_ "embed"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	bbsg2 "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
)

const (
	// Case 16 (https://github.com/w3c-ccg/vc-http-api/pull/128)
	TestVector1       string = "case16_vc.jsonld"
	TestVector1Reveal string = "case16_reveal_doc.jsonld"
)

var (
	//go:embed testdata
	knownTestData embed.FS
)

func TestBBSPlusSignatureProofSuite(t *testing.T) {
	base58PubKey := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
	pubKeyBytes, err := base58.Decode(base58PubKey)
	assert.NoError(t, err)

	case16VC, err := getTestVector(TestVector1)
	assert.NoError(t, err)
	assert.NotEmpty(t, case16VC)

	var cred TestCredential
	err = json.Unmarshal([]byte(case16VC), &cred)
	assert.NoError(t, err)

	pubKey, err := bbsg2.UnmarshalPublicKey(pubKeyBytes)
	assert.NoError(t, err)
	signer := BBSPlusSigner{
		BBSPlusSigner: crypto.BBSPlusSigner{
			PublicKey: pubKey,
		},
	}
	assert.NotEmpty(t, signer)

	case16RevealDoc, err := getTestVector(TestVector1)
	assert.NoError(t, err)
	assert.NotEmpty(t, case16RevealDoc)

	var revealDoc map[string]any
	err = json.Unmarshal([]byte(case16RevealDoc), &revealDoc)
	assert.NoError(t, err)

	suite := GetBBSPlusSignatureProofSuite()
	selectiveDisclosure, err := suite.SelectivelyDisclose(signer, &cred, revealDoc)
	assert.NoError(t, err)
	assert.NotEmpty(t, selectiveDisclosure)
}

func getTestVector(fileName string) (string, error) {
	b, err := knownTestData.ReadFile("testdata/" + fileName)
	return string(b), err
}
