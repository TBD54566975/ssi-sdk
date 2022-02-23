package cryptosuite

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestCredential struct {
	Context           []string               `json:"@context,omitempty"`
	Type              string                 `json:"type,omitempty"`
	Issuer            string                 `json:"issuer,omitempty"`
	IssuanceDate      string                 `json:"issuanceDate,omitempty"`
	CredentialSubject map[string]interface{} `json:"credentialSubject,omitempty"`
	Proof             *Proof                 `json:"proof,omitempty"`
}

func (t *TestCredential) GetProof() *Proof {
	return t.Proof
}

func (t *TestCredential) SetProof(p *Proof) {
	t.Proof = p
}

// tests data from https://github.com/decentralized-identity/JWS-Test-Suite/tree/main/data/credentials
func TestJSONWebSignature2020Suite(t *testing.T) {
	pk, jwk, err := GenerateEd25519JSONWebKey2020()
	assert.NoError(t, err)
	assert.NotEmpty(t, pk)
	assert.NotEmpty(t, jwk)

	tc := TestCredential{
		Context: []string{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		Type:         "VerifiableCredential",
		Issuer:       "did:example:123",
		IssuanceDate: "2021-01-01T19:23:24Z",
	}

	suite := JWSSignatureSuite{}
	privKey, jwk, err := GenerateEd25519JSONWebKey2020()
	assert.NoError(t, err)
	signer, err := NewJSONWebKey2020Signer("test-signer", jwk.KTY, &jwk.CRV, privKey)
	assert.NoError(t, err)

	p, err := suite.CreateProof(signer, &tc)
	assert.NoError(t, err)
	assert.NotEmpty(t, p)

	bytes, err := json.Marshal(p)
	assert.NoError(t, err)
	fmt.Printf("%s", string(bytes))
	//signed, err := SignProvable(pk, &tc)
	//assert.NoError(t, err)
	//assert.NotEmpty(t, signed)
}
