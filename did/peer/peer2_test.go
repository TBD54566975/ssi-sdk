package peer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/did"
)

func TestPeerMethod2(t *testing.T) {
	var d DIDPeer
	kt := crypto.Ed25519

	pubKey, _, err := d.generateKeyByType(crypto.Ed25519)
	assert.NoError(t, err)

	service := did.Service{
		ID:              "myid",
		Type:            PeerDIDCommMessagingAbbr,
		ServiceEndpoint: "https://example.com/endpoint",
		RoutingKeys:     []string{"did:example:somemediator#somekey"},
		Accept:          []string{"didcomm/v2"},
	}

	m2 := PeerMethod2{KT: kt, Values: []any{pubKey, service}}

	didPeer, err := m2.Generate()
	assert.NoError(t, err)
	assert.True(t, didPeer.IsValid())
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
	didPeer := DIDPeer(testDoc.ID)

	resolved, err := PeerMethod2{}.resolve(didPeer, nil)
	assert.NoError(t, err)

	assert.Equal(t, testDoc.Context, resolved.Document.Context)
	assert.Equal(t, testDoc.ID, resolved.ID)

	assert.Equal(t, testDoc.Services[0].ID, resolved.Services[0].ID)
	assert.Equal(t, testDoc.Services[0].Type, resolved.Services[0].Type)
	assert.Equal(t, testDoc.Services[0].ServiceEndpoint, resolved.Services[0].ServiceEndpoint)
	assert.Equal(t, testDoc.Services[0].Accept, resolved.Services[0].Accept)

	assert.Equal(t, testDoc.KeyAgreement[0].(did.VerificationMethod).ID, resolved.KeyAgreement[0].(did.VerificationMethod).ID)
	assert.Equal(t, testDoc.KeyAgreement[0].(did.VerificationMethod).Type, resolved.KeyAgreement[0].(did.VerificationMethod).Type)
	assert.Equal(t, testDoc.KeyAgreement[0].(did.VerificationMethod).Controller, resolved.KeyAgreement[0].(did.VerificationMethod).Controller)
	assert.Equal(t, testDoc.KeyAgreement[0].(did.VerificationMethod).PublicKeyMultibase, resolved.KeyAgreement[0].(did.VerificationMethod).PublicKeyMultibase)

	assert.Equal(t, testDoc.Authentication[0].(did.VerificationMethod).ID, resolved.Authentication[0].(did.VerificationMethod).ID)
	assert.Equal(t, testDoc.Authentication[0].(did.VerificationMethod).Type, resolved.Authentication[0].(did.VerificationMethod).Type)
	assert.Equal(t, testDoc.Authentication[0].(did.VerificationMethod).Controller, resolved.Authentication[0].(did.VerificationMethod).Controller)
	assert.Equal(t, testDoc.Authentication[0].(did.VerificationMethod).PublicKeyMultibase, resolved.Authentication[0].(did.VerificationMethod).PublicKeyMultibase)

	assert.Equal(t, testDoc.Authentication[1].(did.VerificationMethod).ID, resolved.Authentication[1].(did.VerificationMethod).ID)
	assert.Equal(t, testDoc.Authentication[1].(did.VerificationMethod).Type, resolved.Authentication[1].(did.VerificationMethod).Type)
	assert.Equal(t, testDoc.Authentication[1].(did.VerificationMethod).Controller, resolved.Authentication[1].(did.VerificationMethod).Controller)
	assert.Equal(t, testDoc.Authentication[1].(did.VerificationMethod).PublicKeyMultibase, resolved.Authentication[1].(did.VerificationMethod).PublicKeyMultibase)
}
