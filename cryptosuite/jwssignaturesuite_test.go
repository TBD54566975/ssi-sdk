package cryptosuite

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

	p, err := suite.Sign(signer, &tc)
	assert.NoError(t, err)
	assert.NotEmpty(t, p)

	//bytes, err := json.Marshal(p)
	//assert.NoError(t, err)
	//fmt.Printf("%s", string(bytes))

	verifier := NewJSONWebKey2020Verifier(*jwk)
	err = suite.Verify(verifier, *p)
	assert.NoError(t, err)
}

// https://github.com/decentralized-identity/JWS-Test-Suite
func TestTestVectors(t *testing.T) {
	key0JWK := PublicKeyJWK{
		KTY: "OKP",
		CRV: "Ed25519",
		X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
	}

	_, pk, _ := ed25519.GenerateKey(rand.Reader)
	println(base64.URLEncoding.EncodeToString(pk))
	key0D := "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE"
	decodedD, err := base64.URLEncoding.DecodeString(key0D)
	assert.NoError(t, err)

	assert.True(t, len(decodedD) == ed25519.PrivateKeySize)
	keyPair0Private := ed25519.PrivateKey(key0D)
	keyPair0Public := keyPair0Private.Public()

	keyPair0JWK, err := Ed25519JSONWebKey2020(keyPair0Public.([]byte))
	assert.NoError(t, err)
	assert.EqualValues(t, key0JWK, keyPair0JWK)
}
