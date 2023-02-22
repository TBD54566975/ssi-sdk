package cryptosuite

import (
	"embed"
	_ "embed"
	"encoding/base64"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/goccy/go-json"
	bbsg2 "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	t.Run("generate our own credential and frame", func(tt *testing.T) {
		// generate a test credential to selectively disclosure just the issuer
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
		privKey, err := key.GetPrivateKey()
		assert.NoError(t, err)
		signer := NewBBSPlusSigner("test-key-1", privKey, Authentication)
		err = suite.Sign(signer, &testCred)
		assert.NoError(t, err)

		proofSuite := GetBBSPlusSignatureProofSuite()
		revealDoc := map[string]any{
			"@context": []any{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/bbs/v1"},
			"type":     "VerifiableCredential",
			"issuer":   map[string]any{},
		}
		verifier := NewBBSPlusVerifier("test-key-1", privKey.PublicKey())

		nonce, err := base64.StdEncoding.DecodeString("G/hn9Ca9bIWZpJGlhnr/41r8RB0OO0TLChZASr3QJVztdri/JzS8Zf/xWJT5jW78zlM=")
		require.NoError(t, err)

		selectiveDisclosure, err := proofSuite.SelectivelyDisclose(*verifier, &testCred, revealDoc, nonce)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, selectiveDisclosure)

		// now verify the derived credential
		var genericCred credential.GenericCredential
		sdBytes, err := json.Marshal(selectiveDisclosure)
		assert.NoError(tt, err)
		err = json.Unmarshal(sdBytes, &genericCred)
		assert.NoError(tt, err)

		err = proofSuite.Verify(verifier, &genericCred)
		assert.NoError(tt, err)
	})

	t.Run("known test vector", func(tt *testing.T) {
		base58PubKey := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
		pubKeyBytes, err := base58.Decode(base58PubKey)
		assert.NoError(tt, err)

		case16VC, err := getTestVector(TestVector1)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, case16VC)

		var cred TestCredential
		err = json.Unmarshal([]byte(case16VC), &cred)
		assert.NoError(tt, err)

		pubKey, err := bbsg2.UnmarshalPublicKey(pubKeyBytes)
		assert.NoError(tt, err)
		verifier := NewBBSPlusVerifier("test-key-1", pubKey)
		assert.NotEmpty(tt, verifier)

		// First verify the credential as is
		suite := GetBBSPlusSignatureSuite()
		err = suite.Verify(verifier, &cred)
		assert.NoError(tt, err)

		// Test selective disclosure
		proofSuite := GetBBSPlusSignatureProofSuite()
		case16RevealDoc, err := getTestVector(TestVector1Reveal)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, case16RevealDoc)

		var revealDoc map[string]any
		err = json.Unmarshal([]byte(case16RevealDoc), &revealDoc)
		assert.NoError(tt, err)

		nonce, err := base64.StdEncoding.DecodeString("G/hn9Ca9bIWZpJGlhnr/41r8RB0OO0TLChZASr3QJVztdri/JzS8Zf/xWJT5jW78zlM=")
		require.NoError(t, err)

		selectiveDisclosure, err := proofSuite.SelectivelyDisclose(*verifier, &cred, revealDoc, nonce)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, selectiveDisclosure)

		// now verify the derived credential
		var genericCred credential.GenericCredential
		sdBytes, err := json.Marshal(selectiveDisclosure)
		assert.NoError(tt, err)
		err = json.Unmarshal(sdBytes, &genericCred)
		assert.NoError(tt, err)

		err = proofSuite.Verify(verifier, &genericCred)
		assert.NoError(tt, err)
	})
}

func TestRoundTripTestVector(t *testing.T) {
	var cred TestCredential
	tv, err := getTestVector(TestVector1)
	assert.NoError(t, err)
	err = json.Unmarshal([]byte(tv), &cred)
	assert.NoError(t, err)

	credBytes, err := json.Marshal(cred)
	assert.NoError(t, err)
	assert.JSONEq(t, tv, string(credBytes))
}

func getTestVector(fileName string) (string, error) {
	b, err := knownTestData.ReadFile("testdata/" + fileName)
	return string(b), err
}
