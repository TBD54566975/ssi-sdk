//go:build jwx_es256k

package cryptosuite

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestCredential struct {
	Context           []interface{}          `json:"@context,omitempty"`
	Type              []string               `json:"type,omitempty"`
	Issuer            string                 `json:"issuer,omitempty"`
	IssuanceDate      string                 `json:"issuanceDate,omitempty"`
	ExpirationDate    string                 `json:"expirationDate,omitempty"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	Evidence          []interface{}          `json:"evidence,omitempty"`
	Proof             *Proof                 `json:"proof,omitempty"`
}

func (t *TestCredential) GetProof() *Proof {
	return t.Proof
}

func (t *TestCredential) SetProof(p *Proof) {
	t.Proof = p
}

func TestJSONWebKey2020ToJWK(t *testing.T) {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	signer, jwk := getTestVectorKey0Signer(t, AssertionMethod)
	verifier, err := NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
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
			crv:       Secp256k1,
			expectErr: false,
		},
		{
			name:      "secp256k1 as OKP",
			kty:       OKP,
			crv:       Secp256k1,
			expectErr: true,
		},
		{
			name:      "unsupported curve",
			kty:       EC,
			crv:       "P512",
			expectErr: true,
		},
	}

	suite := GetJSONWebSignature2020Suite()
	testCred := TestCredential{
		Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
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
		t.Run(test.name, func(tt *testing.T) {
			jwk, err := GenerateJSONWebKey2020(test.kty, test.crv)

			if !test.expectErr {
				signer, err := NewJSONWebKeySigner(jwk.ID, jwk.PrivateKeyJWK, AssertionMethod)
				assert.NoError(tt, err)

				// pin to avoid ptr shadowing
				credPtr := testCred
				err = suite.Sign(signer, &credPtr)
				assert.NoError(tt, err)

				verifier, err := NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
				assert.NoError(tt, err)

				// pin to avoid ptr shadowing
				verifyPtr := credPtr
				err = suite.Verify(verifier, &verifyPtr)
				assert.NoError(tt, err)
			} else {
				assert.Error(tt, err)
			}
		})
	}
}

// https://github.com/decentralized-identity/JWS-Test-Suite
func TestJsonWebSignature2020TestVectorCredential0(t *testing.T) {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	signer, jwk := getTestVectorKey0Signer(t, AssertionMethod)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/credentials/credential-0.json
	knownCred := TestCredential{
		Context:           []interface{}{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		Type:              []string{"VerifiableCredential"},
		Issuer:            "did:example:123",
		IssuanceDate:      "2021-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{},
	}

	suite := GetJSONWebSignature2020Suite()
	err := suite.Sign(&signer, &knownCred)
	assert.NoError(t, err)

	verifier, err := NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
	assert.NoError(t, err)

	// first verify our credential
	err = suite.Verify(verifier, &knownCred)
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
	knownCredSigned := knownCred
	knownCredSigned.SetProof(&proof)

	// verify known cred
	err = suite.Verify(verifier, &knownCredSigned)
	assert.NoError(t, err)
}

func TestJsonWebSignature2020TestVectorsCredential1(t *testing.T) {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	signer, jwk := getTestVectorKey0Signer(t, AssertionMethod)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/credentials/credential-1.json
	knownCred := TestCredential{
		Context:        []interface{}{"https://www.w3.org/2018/credentials/v1", "https://w3id.org/security/suites/jws-2020/v1", map[string]string{"@vocab": "https://example.com/#"}},
		Type:           []string{"VerifiableCredential"},
		Issuer:         "did:example:123",
		IssuanceDate:   "2021-01-01T19:23:24Z",
		ExpirationDate: "2031-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{
			"id":   "did:example:456",
			"type": "Person",
		},
	}

	suite := GetJSONWebSignature2020Suite()
	err := suite.Sign(&signer, &knownCred)
	assert.NoError(t, err)

	verifier, err := NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
	assert.NoError(t, err)

	// verify our credential
	err = suite.Verify(verifier, &knownCred)
	assert.NoError(t, err)
}

type TestPresentation struct {
	Context              interface{}      `json:"@context" validate:"required"`
	ID                   string           `json:"id,omitempty"`
	Holder               string           `json:"holder,omitempty"`
	Type                 interface{}      `json:"type" validate:"required"`
	VerifiableCredential []TestCredential `json:"verifiableCredential,omitempty" validate:"omitempty,dive"`
	Proof                *Proof           `json:"proof,omitempty"`
}

func (t *TestPresentation) GetProof() *Proof {
	return t.Proof
}

func (t *TestPresentation) SetProof(p *Proof) {
	t.Proof = p
}

func TestJsonWebSignature2020TestVectorPresentation1(t *testing.T) {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	signer, jwk := getTestVectorKey0Signer(t, Authentication)

	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/presentations/presentation-1.json
	var credProof Proof = map[string]interface{}{
		"type":               "JsonWebSignature2020",
		"created":            "2021-10-02T17:58:00Z",
		"proofPurpose":       "assertionMethod",
		"verificationMethod": "did:example:123#key-0",
		"jws":                "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..VA8VQqAerUT6AIVdHc8W8Q2aj12LOQjV_VZ1e134NU9Q20eBsNySPjNdmTWp2HkdquCnbRhBHxIbNeFEIOOhAg",
	}
	knownPres := TestPresentation{
		Context: []string{"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/security/suites/jws-2020/v1"},
		ID:     "urn:uuid:789",
		Holder: "did:example:123",
		Type:   []string{"VerifiablePresentation"},
		VerifiableCredential: []TestCredential{
			{
				Context: []interface{}{"https://www.w3.org/2018/credentials/v1",
					"https://w3id.org/security/suites/jws-2020/v1",
					map[string]interface{}{
						"@vocab": "https://example.com/#",
					}},
				Type:         []string{"VerifiableCredential"},
				Issuer:       "did:example:123",
				IssuanceDate: "2021-01-01T19:23:24Z",
				CredentialSubject: map[string]interface{}{
					"id": "did:example:456",
				},
				Evidence: []interface{}{
					map[string]interface{}{
						"id":               "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192d4231",
						"type":             []string{"DocumentVerification"},
						"verifier":         "https://example.edu/issuers/14",
						"evidenceDocument": "DriversLicense",
						"subjectPresence":  "Physical",
						"documentPresence": "Physical",
					},
					map[string]interface{}{
						"id":               "https://example.edu/evidence/f2aeec97-fc0d-42bf-8ca7-0548192dxyzab",
						"type":             []string{"SupportingActivity"},
						"verifier":         "https://example.edu/issuers/14",
						"evidenceDocument": "Fluid Dynamics Focus",
						"subjectPresence":  "Digital",
						"documentPresence": "Digital",
					},
				},
				Proof: &credProof,
			},
		},
	}

	// sign known pres
	suite := GetJSONWebSignature2020Suite()
	err := suite.Sign(&signer, &knownPres)
	assert.NoError(t, err)

	verifier, err := NewJSONWebKeyVerifier(jwk.ID, jwk.PublicKeyJWK)
	assert.NoError(t, err)

	// verify our presentation
	err = suite.Verify(verifier, &knownPres)
	assert.NoError(t, err)

	// verify against known working impl
	// https://identity.foundation/JWS-Test-Suite/implementations/transmute/presentation-1--key-0-ed25519.vp.json
	var knownProof Proof = map[string]interface{}{
		"type":               "JsonWebSignature2020",
		"created":            "2022-03-08T23:38:19Z",
		"verificationMethod": "did:example:123#key-0",
		"proofPurpose":       "authentication",
		"challenge":          "123",
		"jws":                "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..2Lckee0hjEiXlvl3X-Sp4ghqhc6HAH1AjnGwAYWC71i6k84U5ajb79aUWfwxUIMdQcE-hwbU6roUfsMWliDxAA",
	}
	signedPres := knownPres
	signedPres.SetProof(&knownProof)

	// verify known proof
	err = suite.Verify(verifier, &signedPres)
	assert.NoError(t, err)
}

func getTestVectorKey0Signer(t *testing.T, purpose ProofPurpose) (JSONWebKeySigner, JSONWebKey2020) {
	// https://github.com/decentralized-identity/JWS-Test-Suite/blob/main/data/keys/key-0-ed25519.json
	knownJWK := JSONWebKey2020{
		ID: "did:example:123#key-0",
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

	signer, err := NewJSONWebKeySigner(knownJWK.ID, knownJWK.PrivateKeyJWK, purpose)
	assert.NoError(t, err)
	return *signer, knownJWK
}
