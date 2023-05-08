package peer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
)

func TestPeerMethod0(t *testing.T) {
	var m0 Method0
	kt := crypto.Ed25519

	// TODO: Add known key so reproducible results
	pubKey, _, err := crypto.GenerateKeyByKeyType(kt)
	assert.NoError(t, err)

	didPeer, err := m0.Generate(kt, pubKey)
	assert.NoError(t, err)

	resolved, err := m0.resolve(*didPeer, nil)
	assert.NoError(t, err)
	testDoc := makeSamplePeerDIDDocument0()

	assert.Equal(t, testDoc.Context, resolved.Document.Context)
}

func TestPeerResolveMethod0(t *testing.T) {
	didPeer := DIDPeer("did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	resolved, err := Method0{}.resolve(didPeer, nil)
	assert.NoError(t, err)
	testDoc := getSampleDIDDocumentMethod0()
	assert.Equal(t, testDoc.Context, resolved.Document.Context)
	assert.Equal(t, testDoc.ID, resolved.ID)
}

func makeSamplePeerDIDDocument0() *did.Document {
	return &did.Document{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:peer:0z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs",
		Authentication: []did.VerificationMethodSet{
			did.VerificationMethod{
				ID:              "#z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6",
				Type:            "Ed25519VerificationKey2018",
				Controller:      "id:peer:0z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6",
				PublicKeyBase58: "FhV92MLqMGanvJbgnGY2Kjxi4tbXZWZbauHW58R9315i",
			},
		},
		KeyAgreement: []did.VerificationMethodSet{
			[]string{"#z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6"},
		},
		AssertionMethod: []did.VerificationMethodSet{
			[]string{"#z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6"},
		},
		CapabilityDelegation: []did.VerificationMethodSet{
			[]string{"#z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6"},
		},
	}
}
