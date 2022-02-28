//go:build jwx_es256k

package cryptosuite

import (
	"encoding/json"
	"testing"

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

	signer, err := NewJSONWebKeySigner(knownJWK.PrivateKeyJWK)
	assert.NoError(t, err)
	verifier, err := NewJSONWebKeyVerifier(knownJWK.PublicKeyJWK)
	assert.NoError(t, err)

	msg := []byte("hello")
	sig, err := signer.Sign(msg)
	assert.NoError(t, err)

	err = verifier.Verify(msg, sig)
	assert.NoError(t, err)
}

func TestJsonWebSignature2020AllKeyTypes(t *testing.T) {
	tests := []struct {
		name      string
		kty       KTY
		crv       CRV
		expectErr bool
	}{
		{
			name:      "RSA",
			kty:       RSA,
			expectErr: false,
		},
		{
			name:      "RSA with CRV",
			kty:       RSA,
			crv:       Ed25519,
			expectErr: true,
		},
		{
			name:      "Ed25519",
			kty:       OKP,
			crv:       Ed25519,
			expectErr: false,
		},
		{
			name:      "Ed25519 with EC",
			kty:       EC,
			crv:       Ed25519,
			expectErr: true,
		},
		{
			name:      "P-256",
			kty:       EC,
			crv:       P256,
			expectErr: false,
		},
		{
			name:      "P-384",
			kty:       EC,
			crv:       P384,
			expectErr: false,
		},
		{
			name:      "secp256k1",
			kty:       EC,
			crv:       SECP256k1,
			expectErr: false,
		},
		{
			name:      "secp256k1 as OKP",
			kty:       OKP,
			crv:       SECP256k1,
			expectErr: true,
		},
		{
			name:      "unsupported curve",
			kty:       EC,
			crv:       "P512",
			expectErr: true,
		},
	}

	suite := JWSSignatureSuite{}
	testCred := TestCredential{
		Context: []string{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		Type:         []string{"VerifiableCredential"},
		Issuer:       "did:example:123",
		IssuanceDate: "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{
			"id":        "did:example:abcd",
			"firstName": "Satoshi",
			"lastName":  "Nakamoto",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jwk, err := GenerateJSONWebKey2020(test.kty, crvPtr(test.crv))

			if !test.expectErr {
				signer, err := NewJSONWebKeySigner(jwk.PrivateKeyJWK)
				assert.NoError(t, err)

				p, err := suite.Sign(signer, &testCred)
				assert.NoError(t, err)
				assert.NotEmpty(t, p)

				verifier, err := NewJSONWebKeyVerifier(jwk.PublicKeyJWK)
				assert.NoError(t, err)
				err = suite.Verify(verifier, *p)
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
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

	signer, err := NewJSONWebKeySigner(knownJWK.PrivateKeyJWK)
	assert.NoError(t, err)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/credentials/credential-0.json
	knownCred := TestCredential{
		Context:           []string{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{},
	}

	suite := JWSSignatureSuite{}
	p, err := suite.Sign(signer, &knownCred)
	assert.NoError(t, err)

	b, _ := json.Marshal(p)
	println(string(b))

	verifier, err := NewJSONWebKeyVerifier(knownJWK.PublicKeyJWK)
	assert.NoError(t, err)

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
