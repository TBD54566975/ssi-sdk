package cryptosuite

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

type TestCredential struct {
	Context           []string               `json:"@context,omitempty"`
	Type              []string               `json:"type,omitempty"`
	Issuer            string                 `json:"issuer,omitempty"`
	IssuanceDate      string                 `json:"issuanceDate,omitempty"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Proof             Proof                  `json:"proof,omitempty"`
}

func (t *TestCredential) GetProof() *Proof {
	return &t.Proof
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
		Type:         []string{"VerifiableCredential"},
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

	verifier := NewJSONWebKey2020Verifier(*jwk)
	err = suite.Verify(verifier, *p)
	assert.NoError(t, err)
}

// https://github.com/decentralized-identity/JWS-Test-Suite
func TestJsonWebSignature2020TestVectors(t *testing.T) {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	knownJWK := JSONWebKey2020{
		PublicKeyJWK: PublicKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
		},
		PrivateKeyJWK: PrivateKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
		},
	}

	privJWKBytes, err := json.Marshal(knownJWK.PrivateKeyJWK)
	assert.NoError(t, err)

	privJWK, err := jwk.ParseKey(privJWKBytes)
	assert.NoError(t, err)

	suite := JWSSignatureSuite{}

	signer := NewSignerbro(privJWK)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/credentials/credential-0.json
	knownCred := TestCredential{
		Context:           []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{},
	}

	p, err := suite.Sign(signer, &knownCred)
	assert.NoError(t, err)

	pb, _ := json.Marshal(p)
	println(string(pb))

	pubJWKBytes, err := json.Marshal(knownJWK.PublicKeyJWK)
	assert.NoError(t, err)
	pubJWK, err := jwk.ParseKey(pubJWKBytes)
	assert.NoError(t, err)

	verifier := NewVerifierbro(pubJWK)

	// first verify our credential
	err = suite.Verify(verifier, *p)
	assert.NoError(t, err)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/implementations/transmute/credential-0--key-0-ed25519.vc.json
	knownProof := JsonWebSignature2020Proof{
		Type:               "JsonWebSignature2020",
		Created:            "2022-01-24T23:26:38Z",
		JWS:                "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..377mL0aIk_YL_scEZh1BIzje17vD4F7U8WPo2ufgkkGLwDNXHDhN99zpnsvsozD5Si82gRbDHqFu3Rp6dLH7Ag",
		ProofPurpose:       "assertionMethod",
		VerificationMethod: "did:example:123#key-0",
	}
	proof := knownProof.ToGenericProof()
	knownCredSigned := TestCredential{
		Context:           []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{},
		Proof:             &proof,
	}
	// verify known cred
	err = suite.Verify(verifier, &knownCredSigned)
	assert.NoError(t, err)
}

func TestJSONWebKey2020ToJWK(t *testing.T) {
	knownJWK := JSONWebKey2020{
		PublicKeyJWK: PublicKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
		},
		PrivateKeyJWK: PrivateKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
			D:   "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
		},
	}

	privJWKBytes, err := json.Marshal(knownJWK.PrivateKeyJWK)
	assert.NoError(t, err)

	privJWK, err := jwk.ParseKey(privJWKBytes)
	assert.NoError(t, err)

	pubJWKBytes, err := json.Marshal(knownJWK.PublicKeyJWK)
	assert.NoError(t, err)
	pubJWK, err := jwk.ParseKey(pubJWKBytes)
	assert.NoError(t, err)

	signer := NewSignerbro(privJWK)
	verifier := NewVerifierbro(pubJWK)

	msg := []byte("hello")
	sig, err := signer.Sign(msg)
	assert.NoError(t, err)

	err = verifier.Verify(msg, sig)
	assert.NoError(t, err)
}
