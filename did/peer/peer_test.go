package peer

import (
	"context"
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"

	"github.com/stretchr/testify/assert"
)

func TestEncodePublicKeyWithKeyMultiCodecType(t *testing.T) {
	// unsupported type
	_, err := encodePublicKeyWithKeyMultiCodecType(crypto.KeyType("unsupported"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a supported key type")

	// bad public key
	_, err = encodePublicKeyWithKeyMultiCodecType(crypto.Ed25519, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown public key type; could not convert to bytes")
}

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
		sbe := did.Service{
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

func makeSamplePeerDIDDocument() *did.Document {
	return &did.Document{
		Context: "https://w3id.org/did/v1",
		ID:      "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
		Authentication: []did.VerificationMethodSet{
			did.VerificationMethod{
				ID:                 "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0#6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
				PublicKeyMultibase: "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
			},
			did.VerificationMethod{
				ID:                 "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0#6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg",
				Type:               "Ed25519VerificationKey2020",
				Controller:         "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
				PublicKeyMultibase: "z6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg",
			},
		},
		KeyAgreement: []did.VerificationMethodSet{
			did.VerificationMethod{
				ID:                 "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0#6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
				Type:               "X25519KeyAgreementKey2020",
				Controller:         "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0",
				PublicKeyMultibase: "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
			},
		},
		Services: []did.Service{did.Service{
			ID:              "did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.Vz6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V.Vz6MkgoLTnTypo3tDRwCkZXSccTPHRLhF4ZnjhueYAFpEX6vg.SeyJ0IjoiZG0iLCJzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS9lbmRwb2ludCIsInIiOlsiZGlkOmV4YW1wbGU6c29tZW1lZGlhdG9yI3NvbWVrZXkiXSwiYSI6WyJkaWRjb21tL3YyIiwiZGlkY29tbS9haXAyO2Vudj1yZmM1ODciXX0#didcommmessaging-0",
			Type:            "DIDCommMessaging",
			ServiceEndpoint: "https://example.com/endpoint",
			RoutingKeys:     []string{"did:example:somemediator#somekey"},
			Accept:          []string{"didcomm/v2", "didcomm/aip2;env=rfc587"},
		}},
	}
}

func getSampleDIDDocumentMethod0() *did.Document {
	return &did.Document{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      "did:peer:0z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
	}
}
