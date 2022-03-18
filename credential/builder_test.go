//go:build jwx_es256k

package credential

import (
	"testing"

	"github.com/TBD54566975/did-sdk/util"

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

// Exercise all builder methods
func TestCredentialBuilder(t *testing.T) {
	builder := NewCredentialBuilder()
	_, err := builder.Build()
	assert.Error(t, err)
	notReadyErr := "credential not ready to be built"
	assert.Contains(t, err.Error(), notReadyErr)

	assert.False(t, builder.IsEmpty())

	// default context should be set
	assert.NotEmpty(t, builder.Context)

	// set context of a bad type
	err = builder.SetContext(4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed context")

	// correct context
	err = builder.SetContext("https://www.w3.org/2018/credentials/examples/v1")
	assert.NoError(t, err)

	// there is a default id
	assert.NotEmpty(t, builder.ID)

	// set id
	id := "test-id"
	err = builder.SetID(id)
	assert.NoError(t, err)

	// set bad type value
	err = builder.SetType(5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed type")

	// valid type as a string
	err = builder.SetType("TestType")
	assert.NoError(t, err)

	// valid type as a []string
	err = builder.SetType([]string{"TestType"})
	assert.NoError(t, err)

	// set issuer as a string
	err = builder.SetIssuer("issuer")
	assert.NoError(t, err)

	// reset issuer as an object without an id property
	badIssuerObject := map[string]interface{}{
		"issuer": "abcd",
		"bad":    "efghi",
	}
	err = builder.SetIssuer(badIssuerObject)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer object did not contain `id` property")

	// issuer object with an id property
	goodIssuerObject := map[string]interface{}{
		"id": "issuer",
	}
	err = builder.SetIssuer(goodIssuerObject)
	assert.NoError(t, err)

	// bad date
	err = builder.SetIssuanceDate("not-a-date")
	assert.Error(t, err)

	// good date
	issuedAt := util.GetRFC3339Timestamp()
	err = builder.SetIssuanceDate(issuedAt)
	assert.NoError(t, err)

	// bad date
	err = builder.SetExpirationDate("not-a-date")
	assert.Error(t, err)

	// good date
	expiresAt := util.GetRFC3339Timestamp()
	err = builder.SetExpirationDate(expiresAt)
	assert.NoError(t, err)

	// incomplete credential status
	badStatus := CredentialStatus{
		Type: "StatusObject",
	}
	err = builder.SetCredentialStatus(badStatus)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential status not valid")

	// good status
	status := CredentialStatus{
		ID:   "status-id",
		Type: "status-type",
	}
	err = builder.SetCredentialStatus(status)
	assert.NoError(t, err)

	// bad cred subject - no id
	badSubject := CredentialSubject{
		"name": "Satoshi",
	}
	err = builder.SetCredentialSubject(badSubject)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential subject must have an ID property")

	// good subject
	subject := CredentialSubject{
		"id":   "subject-id",
		"name": "Satoshi",
	}
	err = builder.SetCredentialSubject(subject)
	assert.NoError(t, err)

	// bad cred schema - missing field
	badSchema := CredentialSchema{
		ID: "schema-id",
	}
	err = builder.SetCredentialSchema(badSchema)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential schema not valid")

	// good cred schema
	schema := CredentialSchema{
		ID:   "schema-id",
		Type: "schema-type",
	}
	err = builder.SetCredentialSchema(schema)
	assert.NoError(t, err)

	// bad refresh service - missing field
	badRefreshService := RefreshService{
		ID: "refresh-id",
	}
	err = builder.SetRefreshService(badRefreshService)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "refresh service not valid")

	// good refresh service
	refreshService := RefreshService{
		ID:   "refresh-id",
		Type: "refresh-type",
	}
	err = builder.SetRefreshService(refreshService)
	assert.NoError(t, err)

	// empty terms
	err = builder.SetTermsOfUse([]TermsOfUse{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "terms of use cannot be empty")

	// valid terms
	terms := []TermsOfUse{{Type: "terms", ID: "terms-id"}}
	err = builder.SetTermsOfUse(terms)
	assert.NoError(t, err)

	// empty evidence
	err = builder.SetEvidence([]interface{}{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "evidence cannot be empty")

	// valid evidence
	evidence := []interface{}{"evidence"}
	err = builder.SetEvidence(evidence)
	assert.NoError(t, err)

	// build it and verify some values
	cred, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, cred)
	assert.Equal(t, id, cred.ID)
	assert.Equal(t, issuedAt, cred.IssuanceDate)
	assert.Equal(t, expiresAt, cred.ExpirationDate)
	assert.Equal(t, goodIssuerObject, cred.Issuer)
	assert.Equal(t, schema, *cred.CredentialSchema)
	assert.Equal(t, subject, cred.CredentialSubject)
	assert.Equal(t, evidence, cred.Evidence)
	assert.Equal(t, terms, cred.TermsOfUse)
}
