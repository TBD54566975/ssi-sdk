package did

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
)

func TestDIDPeerValid(t *testing.T) {
	valid := "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	invalid := "did:peer:az6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	assert.True(t, DIDPeer(valid).IsValid())
	assert.False(t, DIDPeer(invalid).IsValid())
}

func makeSamplePeerDIDDocument1() *DIDDocument {

	return &DIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:peer:0z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs",
		Authentication: []VerificationMethodSet{
			VerificationMethod{
				ID:              "#z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6",
				Type:            "Ed25519VerificationKey2018",
				Controller:      "id:peer:0z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6",
				PublicKeyBase58: "FhV92MLqMGanvJbgnGY2Kjxi4tbXZWZbauHW58R9315i",
			},
		},
		KeyAgreement: []VerificationMethodSet{
			[]string{"#z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6"},
		},
		AssertionMethod: []VerificationMethodSet{
			[]string{"#z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6"},
		},
		CapabilityDelegation: []VerificationMethodSet{
			[]string{"#z6Mku9kBcbbGgp5G2oSPTqVsAqWhtTsNyPoxGvCRuQP9xDs6"},
		},
	}
}

func TestPeerMethod0(t *testing.T) {

	kt := crypto.Ed25519
	var m0 PeerMethod0

	// TODO: Add known key so reproducible results
	pubKey, _, err := crypto.GenerateKeyByKeyType(kt)
	assert.NoError(t, err)

	did, err := m0.Generate(kt, pubKey)
	assert.NoError(t, err)

	doc, _, _, err := m0.Resolve(*did, nil)
	assert.NoError(t, err)
	testDoc := makeSamplePeerDIDDocument1()

	assert.Equal(t, testDoc.Context, doc.Context)

}

func TestPeerMethod2(t *testing.T) {

	var d DIDPeer
	kt := crypto.Ed25519

	pubKey, _, err := d.generateKeyByType(crypto.Ed25519)
	assert.NoError(t, err)

	service := Service{
		ID:              "myid",
		Type:            PeerDIDCommMessagingAbbr,
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"did:example:somemediator#somekey"},
		Accept:          []string{"didcomm/v2"},
	}

	m2 := PeerMethod2{KT: kt, Values: []interface{}{pubKey, service}}

	did, err := m2.Generate()
	assert.NoError(t, err)
	assert.True(t, did.IsValid())
}

func makeSamplePeerDIDDocument() *DIDDocument {

	return &DIDDocument{
		Context: "https://w3id.org/did/v1",
		ID:      "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
		Authentication: []VerificationMethodSet{
			VerificationMethod{
				ID:                 "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
			VerificationMethod{
				ID:                 "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0#6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
				PublicKeyMultibase: "z6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg",
			},
		},
		KeyAgreement: []VerificationMethodSet{
			VerificationMethod{
				ID:                 "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0#6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
				Type:               "X25519KeyAgreementKey2020",
				Controller:         "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
				PublicKeyMultibase: "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
			},
		},
		Services: []Service{Service{
			ID:              "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0#didcommmessaging-0",
			Type:            "DIDCommMessaging",
			ServiceEndpoint: "https://example.com/endpoint",
			RoutingKeys:     []string{"did:example:somemediator#somekey"},
			Accept:          []string{"didcomm/v2", "didcomm/aip2;env=rfc587"},
		}},
	}
}

func getSampleDIDDocumentMethod0() *DIDDocument {
	return &DIDDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
	}
}

func TestPeerResolveMethod0(t *testing.T) {
	did := DIDPeer("did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	didDoc, _, _, err := PeerMethod0{}.Resolve(did, nil)
	assert.NoError(t, err)
	gtestDoc := getSampleDIDDocumentMethod0()
	assert.Equal(t, gtestDoc.Context, didDoc.Context)
	assert.Equal(t, gtestDoc.ID, didDoc.ID)
}

// Encoded Encryption Key: .Ez6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
// Encoded Signing Key: .VzXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMyppzx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY
// Service Block:
// {
// 	"type": "DIDCommMessaging",
// 	"serviceEndpoint": "https://example.com/endpoint",
// 	"routingKeys": ["did:example:somemediator#somekey"],
//           "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
// }
// Service Block, after whitespace removal and common word substitution:
// {"t":"dm","s":"https://example.com/endpoint","r":["did:example:somemediator#somekey"],"a":["didcomm/v2","didcomm/aip2;env=rfc587"]}
// Encoded Service Endpoint: .SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=
// Method 2 peer DID: did:peer:2.Ez6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH.VzXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMyppzx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=
func TestPeerResolveMethod2(t *testing.T) {

	testDoc := makeSamplePeerDIDDocument()
	did := DIDPeer(testDoc.ID)

	doc, _, _, err := did.Resolve()
	assert.NoError(t, err)

	assert.Equal(t, testDoc.Context, doc.Context)
	assert.Equal(t, testDoc.ID, doc.ID)

	assert.Equal(t, testDoc.Services[0].ID, doc.Services[0].ID)
	assert.Equal(t, testDoc.Services[0].Type, doc.Services[0].Type)
	assert.Equal(t, testDoc.Services[0].ServiceEndpoint, doc.Services[0].ServiceEndpoint)
	assert.Equal(t, testDoc.Services[0].Accept, doc.Services[0].Accept)

	assert.Equal(t, testDoc.KeyAgreement[0].(VerificationMethod).ID, doc.KeyAgreement[0].(VerificationMethod).ID)
	assert.Equal(t, testDoc.KeyAgreement[0].(VerificationMethod).Type, doc.KeyAgreement[0].(VerificationMethod).Type)
	assert.Equal(t, testDoc.KeyAgreement[0].(VerificationMethod).Controller, doc.KeyAgreement[0].(VerificationMethod).Controller)
	assert.Equal(t, testDoc.KeyAgreement[0].(VerificationMethod).PublicKeyMultibase, doc.KeyAgreement[0].(VerificationMethod).PublicKeyMultibase)

	assert.Equal(t, testDoc.Authentication[0].(VerificationMethod).ID, doc.Authentication[0].(VerificationMethod).ID)
	assert.Equal(t, testDoc.Authentication[0].(VerificationMethod).Type, doc.Authentication[0].(VerificationMethod).Type)
	assert.Equal(t, testDoc.Authentication[0].(VerificationMethod).Controller, doc.Authentication[0].(VerificationMethod).Controller)
	assert.Equal(t, testDoc.Authentication[0].(VerificationMethod).PublicKeyMultibase, doc.Authentication[0].(VerificationMethod).PublicKeyMultibase)

	assert.Equal(t, testDoc.Authentication[1].(VerificationMethod).ID, doc.Authentication[1].(VerificationMethod).ID)
	assert.Equal(t, testDoc.Authentication[1].(VerificationMethod).Type, doc.Authentication[1].(VerificationMethod).Type)
	assert.Equal(t, testDoc.Authentication[1].(VerificationMethod).Controller, doc.Authentication[1].(VerificationMethod).Controller)
	assert.Equal(t, testDoc.Authentication[1].(VerificationMethod).PublicKeyMultibase, doc.Authentication[1].(VerificationMethod).PublicKeyMultibase)

}
