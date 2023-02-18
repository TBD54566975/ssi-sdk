package cryptosuite

import (
	_ "embed"
	"testing"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	bbsg2 "github.com/hyperledger/aries-framework-go/pkg/crypto/primitive/bbs12381g2pub"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
)

var (
	//go:embed testdata/case16_vc.jsonld
	case16VC string // Case 16 (https://github.com/w3c-ccg/vc-http-api/pull/128)
	//go:embed testdata/case16_reveal_doc.jsonld
	case16RevealDoc string
)

func TestBBSPlusSignatureProofSuite(t *testing.T) {
	base58PubKey := "nEP2DEdbRaQ2r5Azeatui9MG6cj7JUHa8GD7khub4egHJREEuvj4Y8YG8w51LnhPEXxVV1ka93HpSLkVzeQuuPE1mH9oCMrqoHXAKGBsuDT1yJvj9cKgxxLCXiRRirCycki"
	pubKeyBytes, err := base58.Decode(base58PubKey)
	assert.NoError(t, err)

	var cred credential.VerifiableCredential
	vcBytes, err := json.Marshal(case16VC)
	assert.NoError(t, err)

	err = json.Unmarshal(vcBytes, &cred)
	assert.NoError(t, err)

	pubKey, err := bbsg2.UnmarshalPublicKey(pubKeyBytes)
	assert.NoError(t, err)
	signer := BBSPlusSigner{
		BBSPlusSigner: crypto.BBSPlusSigner{
			PublicKey: pubKey,
		},
	}

	var revealDoc map[string]any
	revealDocBytes, err := json.Marshal(case16RevealDoc)
	assert.NoError(t, err)

	err = json.Unmarshal(revealDocBytes, &revealDoc)
	assert.NoError(t, err)

	suite := GetBBSPlusSignatureProofSuite()
	selectiveDisclosure, err := suite.SelectivelyDisclose(signer, &cred, revealDoc)
	assert.NoError(t, err)
	assert.NotEmpty(t, selectiveDisclosure)
}
