package did

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
)

func TestDIDPeerValid(t *testing.T) {
	valid := "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	invalid := "did:peer:az6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	assert.True(t, DIDPeer(valid).IsValid())
	assert.False(t, DIDPeer(invalid).IsValid())

	assert.True(t, isPeerDID(valid))
	assert.False(t, isPeerDID(invalid))
}

func TestDIDPeerUtilities(t *testing.T) {
	validDIDPeerStr := "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	invalidDIDPeerStr := "did:peer:az6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	invalidDIDPeerMethodStr := "did:peer:4z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"

	t.Run("test string method", func(tt *testing.T) {
		assert.Equal(tt, validDIDPeerStr, DIDPeer(validDIDPeerStr).String())
	})

	t.Run("test did:peer suffix", func(tt *testing.T) {
		did := DIDPeer(validDIDPeerStr)
		d, err := did.Suffix()
		assert.NoError(tt, err)
		assert.Equal(tt, validDIDPeerStr[10:], d)
	})

	t.Run("test invalid format did:peer ", func(tt *testing.T) {
		did := DIDPeer(invalidDIDPeerStr)
		_, err := did.Suffix()
		assert.Error(tt, err)
	})

	t.Run("test suffix function against method 1", func(tt *testing.T) {
		ds := "did:peer:1z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		did := DIDPeer(ds)
		_, err := did.Suffix()
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "method not supported")
	})

	t.Run("test suffix method against unknown method", func(tt *testing.T) {
		did := DIDPeer(invalidDIDPeerMethodStr)
		_, err := did.Suffix()
		assert.Error(tt, err)
	})

	t.Run("test resolve method 1", func(tt *testing.T) {
		var m1 PeerMethod1
		_, err := m1.resolve(DIDPeer("did:peer:1z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"), nil)
		assert.Error(tt, err)
	})

	t.Run("test suffix empty", func(tt *testing.T) {
		did := DIDPeer("")
		_, err := did.Suffix()
		assert.Error(tt, err)
	})

	t.Run("test generate key by type", func(tt *testing.T) {
		badKt := crypto.KeyType("bad")
		goodKT := crypto.Ed25519
		did := DIDPeer(validDIDPeerStr)
		_, _, err := did.generateKeyByType(badKt)
		assert.Error(tt, err)
		publicKey, privKey, err := did.generateKeyByType(goodKT)
		assert.NoError(tt, err)
		assert.NotNil(tt, publicKey)
		assert.NotNil(tt, privKey)
	})

	t.Run("test valid purpose", func(tt *testing.T) {
		did := DIDPeer(validDIDPeerStr)
		assert.True(tt, did.IsValidPurpose(PeerPurposeEncryptionCode))
		assert.False(tt, did.IsValidPurpose(PurposeType("M")))
	})

	t.Run("test valid service block method", func(tt *testing.T) {
		did := DIDPeer("")
		s := ".SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0="
		b := did.checkValidPeerServiceBlock(s)
		assert.True(tt, b)
		s = "bad"
		b = did.checkValidPeerServiceBlock(s)
		assert.False(tt, b)
	})

	t.Run("test avilable peer methods", func(tt *testing.T) {
		assert.True(tt, peerMethodAvailable("0"))
		assert.False(tt, peerMethodAvailable("1"))
		assert.True(tt, peerMethodAvailable("2"))
		assert.False(tt, peerMethodAvailable("3"))
	})

	t.Run("test encode service block", func(tt *testing.T) {
		res := "eyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0"
		sbe := Service{
			Type:            "DIDCommMessaging",
			ServiceEndpoint: "https://example.com/endpoint",
			RoutingKeys:     []string{"did:example:somemediator#somekey"},
			Accept:          []string{"didcomm/v2", "didcomm/aip2;env=rfc587"},
		}
		d := DIDPeer("")
		s2, err := d.encodeService(sbe)
		assert.NoError(tt, err)
		assert.Equal(tt, res, s2)
	})
}

func TestPeerResolver(t *testing.T) {
	bad := "asdf"
	var r PeerResolver
	_, err := r.Resolve(context.Background(), bad, nil)
	assert.Error(t, err)

	m0 := "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	_, err = r.Resolve(context.Background(), m0, nil)
	assert.NoError(t, err)

	mbad := "did:peer:4z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	_, err = r.Resolve(context.Background(), mbad, nil)
	assert.Error(t, err)

	// https://identity.foundation/peer-did-method-spec/#multi-key-creation - key agreement
	m2 := "did:peer:2.Ez6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0="
	_, err = r.Resolve(context.Background(), m2, nil)
	assert.NoError(t, err)

	// https://identity.foundation/peer-did-method-spec/#multi-key-creation w/ key agreement
	// We currently don't support key agreement, so should throw error
	m2 = "did:peer:2.Ez6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH.VzXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMyppzx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0="
	_, err = r.Resolve(context.Background(), m2, nil)
	assert.NoError(t, err)

	m1 := "did:peer:1z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	_, err = r.Resolve(context.Background(), m1, nil)
	assert.Error(t, err)
}

func TestDIDPeerDeltaError(t *testing.T) {
	ds := DIDPeer("did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	_, err := ds.Delta(ds) // delta should be empty
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func makeSamplePeerDIDDocument1() *Document {
	return &Document{
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
	var m0 PeerMethod0
	kt := crypto.Ed25519

	// TODO: Add known key so reproducible results
	pubKey, _, err := crypto.GenerateKeyByKeyType(kt)
	assert.NoError(t, err)

	did, err := m0.Generate(kt, pubKey)
	assert.NoError(t, err)

	resolved, err := m0.resolve(*did, nil)
	assert.NoError(t, err)
	testDoc := makeSamplePeerDIDDocument1()

	assert.Equal(t, testDoc.Context, resolved.Document.Context)
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

	m2 := PeerMethod2{KT: kt, Values: []any{pubKey, service}}

	did, err := m2.Generate()
	assert.NoError(t, err)
	assert.True(t, did.IsValid())
}

func TestPeerMethod1(t *testing.T) {
	var m1 PeerMethod1
	_, err := m1.Generate()
	assert.Error(t, err)
	assert.Contains(t, "not implemented", err.Error())
}

func makeSamplePeerDIDDocument() *Document {
	return &Document{
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

func getSampleDIDDocumentMethod0() *Document {
	return &Document{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
	}
}

func TestPeerResolveMethod0(t *testing.T) {
	did := DIDPeer("did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
	resolved, err := PeerMethod0{}.resolve(did, nil)
	assert.NoError(t, err)
	gtestDoc := getSampleDIDDocumentMethod0()
	assert.Equal(t, gtestDoc.Context, resolved.Document.Context)
	assert.Equal(t, gtestDoc.ID, resolved.ID)
}

// Encoded Encryption Key: .Ez6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH
// Encoded Signing Key: .VzXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMyppzx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY
// Service Block:
//
//	{
//		"type": "DIDCommMessaging",
//		"serviceEndpoint": "https://example.com/endpoint",
//		"routingKeys": ["did:example:somemediator#somekey"],
//	          "accept": ["didcomm/v2", "didcomm/aip2;env=rfc587"]
//	}
//
// Service Block, after whitespace removal and common word substitution:
// {"t":"dm","s":"https://example.com/endpoint","r":["did:example:somemediator#somekey"],"a":["didcomm/v2","didcomm/aip2;env=rfc587"]}
// Encoded Service Endpoint: .SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=
// Method 2 peer DID: did:peer:2.Ez6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH.VzXwpBnMdCm1cLmKuzgESn29nqnonp1ioqrQMRHNsmjMyppzx8xB2pv7cw8q1PdDacSrdWE3dtB9f7Nxk886mdzNFoPtY.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0=
func TestPeerResolveMethod2(t *testing.T) {
	testDoc := makeSamplePeerDIDDocument()
	did := DIDPeer(testDoc.ID)

	resolved, err := PeerMethod2{}.resolve(did, nil)
	assert.NoError(t, err)

	assert.Equal(t, testDoc.Context, resolved.Document.Context)
	assert.Equal(t, testDoc.ID, resolved.ID)

	assert.Equal(t, testDoc.Services[0].ID, resolved.Services[0].ID)
	assert.Equal(t, testDoc.Services[0].Type, resolved.Services[0].Type)
	assert.Equal(t, testDoc.Services[0].ServiceEndpoint, resolved.Services[0].ServiceEndpoint)
	assert.Equal(t, testDoc.Services[0].Accept, resolved.Services[0].Accept)

	assert.Equal(t, testDoc.KeyAgreement[0].(VerificationMethod).ID, resolved.KeyAgreement[0].(VerificationMethod).ID)
	assert.Equal(t, testDoc.KeyAgreement[0].(VerificationMethod).Type, resolved.KeyAgreement[0].(VerificationMethod).Type)
	assert.Equal(t, testDoc.KeyAgreement[0].(VerificationMethod).Controller, resolved.KeyAgreement[0].(VerificationMethod).Controller)
	assert.Equal(t, testDoc.KeyAgreement[0].(VerificationMethod).PublicKeyMultibase, resolved.KeyAgreement[0].(VerificationMethod).PublicKeyMultibase)

	assert.Equal(t, testDoc.Authentication[0].(VerificationMethod).ID, resolved.Authentication[0].(VerificationMethod).ID)
	assert.Equal(t, testDoc.Authentication[0].(VerificationMethod).Type, resolved.Authentication[0].(VerificationMethod).Type)
	assert.Equal(t, testDoc.Authentication[0].(VerificationMethod).Controller, resolved.Authentication[0].(VerificationMethod).Controller)
	assert.Equal(t, testDoc.Authentication[0].(VerificationMethod).PublicKeyMultibase, resolved.Authentication[0].(VerificationMethod).PublicKeyMultibase)

	assert.Equal(t, testDoc.Authentication[1].(VerificationMethod).ID, resolved.Authentication[1].(VerificationMethod).ID)
	assert.Equal(t, testDoc.Authentication[1].(VerificationMethod).Type, resolved.Authentication[1].(VerificationMethod).Type)
	assert.Equal(t, testDoc.Authentication[1].(VerificationMethod).Controller, resolved.Authentication[1].(VerificationMethod).Controller)
	assert.Equal(t, testDoc.Authentication[1].(VerificationMethod).PublicKeyMultibase, resolved.Authentication[1].(VerificationMethod).PublicKeyMultibase)
}
