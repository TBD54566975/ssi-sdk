package cryptosuite

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestCredential struct {
	Context           []string               `json:"@context,omitempty"`
	Type              []string               `json:"type,omitempty"`
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
func TestTestVectors(t *testing.T) {
	// key-0-ed25519.json
	knownJWK := JSONWebKey2020{
		PublicKeyJWK: PublicKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "JYCAGl6C7gcDeKbNqtXBfpGzH0f5elifj7L6zYNj_Is",
		},
		PrivateKeyJWK: PrivateKeyJWK{
			D: "pLMxJruKPovJlxF3Lu_x9Aw3qe2wcj5WhKUAXYLBjwE",
		},
	}

	decodedD, err := base64.RawURLEncoding.DecodeString(knownJWK.D)
	assert.NoError(t, err)
	decodedX, err := base64.RawURLEncoding.DecodeString(knownJWK.X)
	assert.NoError(t, err)
	pkResult := append(decodedD, decodedX...)
	assert.NoError(t, err)

	// reconstruct private key
	privateKey := ed25519.PrivateKey(pkResult)
	// reconstruct pub key
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// reconstruct PublicKeyJWK
	ourJWK, err := Ed25519JSONWebKey2020(publicKey)
	assert.NoError(t, err)
	assert.EqualValues(t, knownJWK.PublicKeyJWK, *ourJWK)

	// credential 0.json
	knownCred := TestCredential{
		Context:           []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{},
	}

	knownProof := JsonWebSignature2020Proof{
		Type:               "JsonWebSignature2020",
		Created:            "2022-01-24T23:24:53.257Z",
		JWS:                "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..lsmHsiYKv4N1Ymifu5SW8sp8FqZNf9J97-iZQo40Ligar2D0zZZdV3BlKrydNM6uifiD8V6RMiiuGkAvmomjCw",
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

	suite := JWSSignatureSuite{}
	signer, err := NewJSONWebKey2020Signer("did:example:123#key-0", ourJWK.KTY, &ourJWK.CRV, &privateKey)
	assert.NoError(t, err)

	// sign with known timestamp for test vector
	p, err := suite.Sign(signer, &knownCred)
	assert.NoError(t, err)

	verifier := NewJSONWebKey2020Verifier(*ourJWK)

	// first verify our credential
	err = suite.Verify(verifier, *p)
	assert.NoError(t, err)

	// verify known credential
	err = suite.Verify(verifier, &knownCredSigned)
	assert.NoError(t, err)
}
