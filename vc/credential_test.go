//go:build jwx_es256k

package vc

import (
	"testing"

	"github.com/TBD54566975/did-sdk/util"

	"github.com/TBD54566975/did-sdk/cryptosuite"

	"github.com/stretchr/testify/assert"
)

func TestCredential(t *testing.T) {
	// happy path build example from the spec
	// https://www.w3.org/TR/vc-data-model/#example-a-simple-example-of-a-verifiable-credential

	knownContext := []string{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"}
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := "https://example.edu/issuers/565049"
	knownIssuanceDate := "2010-01-01T19:23:24Z"
	knownSubject := map[string]interface{}{
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
		"alumniOf": map[string]interface{}{
			"id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
			"name": []interface{}{
				map[string]interface{}{"value": "Example University",
					"lang": "en",
				}, map[string]interface{}{
					"value": "Exemple d'Université",
					"lang":  "fr",
				},
			},
		},
	}

	knownCred := VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	err := knownCred.IsValid()
	assert.NoError(t, err)

	// re-build with our builder
	builder := NewCredentialBuilder()

	err = builder.SetContext(knownContext)
	assert.NoError(t, err)

	err = builder.SetID(knownID)
	assert.NoError(t, err)

	err = builder.SetType(knownType)
	assert.NoError(t, err)

	err = builder.SetIssuer(knownIssuer)
	assert.NoError(t, err)

	err = builder.SetIssuanceDate(knownIssuanceDate)
	assert.NoError(t, err)

	err = builder.SetCredentialSubject(knownSubject)
	assert.NoError(t, err)

	credential, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, credential)

	assert.EqualValues(t, knownCred, *credential)
}

func TestCredentialLDProof(t *testing.T) {
	issuer := "https://example.edu/issuers/565049"
	knownCred := VerifiableCredential{
		Context:      []interface{}{"https://www.w3.org/2018/credentials/v1", "https://www.w3.org/2018/credentials/examples/v1"},
		ID:           "http://example.edu/credentials/1872",
		Type:         []interface{}{"VerifiableCredential", "AlumniCredential"},
		Issuer:       issuer,
		IssuanceDate: "2010-01-01T19:23:24Z",
		CredentialSubject: map[string]interface{}{
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"alumniOf": map[string]interface{}{
				"id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
				"name": []interface{}{
					map[string]interface{}{"value": "Example University",
						"lang": "en",
					}, map[string]interface{}{
						"value": "Exemple d'Université",
						"lang":  "fr",
					},
				},
			},
		},
	}

	// create a copy for value verification later
	var preSigned VerifiableCredential
	err := util.Copy(&knownCred, &preSigned)
	assert.NoError(t, err)

	err = knownCred.IsValid()
	assert.NoError(t, err)

	jwk, err := cryptosuite.GenerateJSONWebKey2020(cryptosuite.OKP, cryptosuite.Ed25519)
	assert.NoError(t, err)
	assert.NotEmpty(t, jwk)

	signer, err := cryptosuite.NewJSONWebKeySigner(issuer, jwk.PrivateKeyJWK)
	assert.NoError(t, err)
	assert.NotEmpty(t, signer)

	suite := cryptosuite.GetJSONWebSignature2020Suite()

	err = suite.Sign(signer, &knownCred)
	assert.NoError(t, err)

	verifier, err := cryptosuite.NewJSONWebKeyVerifier(issuer, jwk.PublicKeyJWK)
	assert.NoError(t, err)
	assert.NotEmpty(t, verifier)

	err = suite.Verify(verifier, &knownCred)
	assert.NoError(t, err)

	// make sure all values are maintained after signing
	assert.Equal(t, preSigned.Context, knownCred.Context)
	assert.Equal(t, preSigned.ID, knownCred.ID)
	assert.Equal(t, preSigned.Type, knownCred.Type)
	assert.Equal(t, preSigned.Issuer, knownCred.Issuer)
	assert.Equal(t, preSigned.IssuanceDate, knownCred.IssuanceDate)
	assert.Equal(t, preSigned.CredentialSubject, knownCred.CredentialSubject)

	// make sure the proof has valid values
	assert.NotEmpty(t, knownCred.Proof)

	// cast to known proof type
	p, ok := (*knownCred.Proof).(cryptosuite.JsonWebSignature2020Proof)
	assert.True(t, ok)
	assert.Equal(t, cryptosuite.JSONWebSignature2020, p.Type)
	assert.NotEmpty(t, p.JWS)
	assert.NotEmpty(t, p.Created)
	assert.Equal(t, issuer, p.VerificationMethod)
}
