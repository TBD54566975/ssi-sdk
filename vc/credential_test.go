//go:build jwx_es256k

package vc

import (
	"testing"

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
