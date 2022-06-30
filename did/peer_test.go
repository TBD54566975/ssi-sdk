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

func TestPeerMethod2(t *testing.T) {

	var d DIDPeer
	pubKey, _, err := d.generateKeyByType(crypto.Ed25519)
	if err != nil {
		t.Fatal(err)
	}

	k1 := PeerMethod2Declaration{
		Key:     pubKey,
		Purpose: PeerPurposeEncryptionCode,
	}

	k2 := PeerMethod2Declaration{
		Service: Service{
			Type:            PeerDIDCommMessagingAbbr,
			ServiceEndpoint: "https://example.com/endpoint",
			RoutingKeys:     []string{"did:example:somemediator#somekey"},
			Accept:          []string{"didcomm/v2"},
		},
		Purpose: PeerPurposeCapabilityServiceCode,
	}

	m2 := method2{
		kt:   crypto.Ed25519,
		keys: []PeerMethod2Declaration{k1, k2},
	}
	_, did, err := m2.Generate()
	if err != nil {
		t.Fatal(err)
	}
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

	var tDoc = makeSamplePeerDIDDocument()
	did := DIDPeer(tDoc.ID)

	doc, err := did.Resolve()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, tDoc.Context, doc.Context)
	assert.Equal(t, tDoc.ID, doc.ID)

	assert.Equal(t, tDoc.Services[0].ID, doc.Services[0].ID)
	assert.Equal(t, tDoc.Services[0].Type, doc.Services[0].Type)
	assert.Equal(t, tDoc.Services[0].ServiceEndpoint, doc.Services[0].ServiceEndpoint)
	assert.Equal(t, tDoc.Services[0].Accept, doc.Services[0].Accept)

	assert.Equal(t, tDoc.KeyAgreement[0].(VerificationMethod).ID, doc.KeyAgreement[0].(VerificationMethod).ID)
	assert.Equal(t, tDoc.KeyAgreement[0].(VerificationMethod).Type, doc.KeyAgreement[0].(VerificationMethod).Type)
	assert.Equal(t, tDoc.KeyAgreement[0].(VerificationMethod).Controller, doc.KeyAgreement[0].(VerificationMethod).Controller)
	assert.Equal(t, tDoc.KeyAgreement[0].(VerificationMethod).PublicKeyMultibase, doc.KeyAgreement[0].(VerificationMethod).PublicKeyMultibase)

	assert.Equal(t, tDoc.Authentication[0].(VerificationMethod).ID, doc.Authentication[0].(VerificationMethod).ID)
	assert.Equal(t, tDoc.Authentication[0].(VerificationMethod).Type, doc.Authentication[0].(VerificationMethod).Type)
	assert.Equal(t, tDoc.Authentication[0].(VerificationMethod).Controller, doc.Authentication[0].(VerificationMethod).Controller)
	assert.Equal(t, tDoc.Authentication[0].(VerificationMethod).PublicKeyMultibase, doc.Authentication[0].(VerificationMethod).PublicKeyMultibase)

	assert.Equal(t, tDoc.Authentication[1].(VerificationMethod).ID, doc.Authentication[1].(VerificationMethod).ID)
	assert.Equal(t, tDoc.Authentication[1].(VerificationMethod).Type, doc.Authentication[1].(VerificationMethod).Type)
	assert.Equal(t, tDoc.Authentication[1].(VerificationMethod).Controller, doc.Authentication[1].(VerificationMethod).Controller)
	assert.Equal(t, tDoc.Authentication[1].(VerificationMethod).PublicKeyMultibase, doc.Authentication[1].(VerificationMethod).PublicKeyMultibase)

}
