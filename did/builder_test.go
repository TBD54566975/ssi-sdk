package did

import (
	"testing"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/stretchr/testify/assert"
)

// Exercise all builder methods
func TestDIDDocumentBuilder(t *testing.T) {
	// https://www.w3.org/TR/did-core/#example-did-document-with-1-verification-method-type
	var exampleAuthenticationEntry = map[string]string{
		"id":                 "did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3",
		"type":               "Ed25519VerificationKey2020",
		"controller":         "did:example:123",
		"publicKeyMultibase": "zAKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf",
	}

	var exampleCapabilityInvocationEntry = map[string]string{
		"id":                 "did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k",
		"type":               "Ed25519VerificationKey2020",
		"controller":         "did:example:123",
		"publicKeyMultibase": "z4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN",
	}

	var exampleAssertionEntry = map[string]string{
		"id":                 "did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY",
		"type":               "Ed25519VerificationKey2020",
		"controller":         "did:example:123",
		"publicKeyMultibase": "z5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA",
	}

	var exampleCapabilityDelegationEntry = map[string]string{
		"id":                 "did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi",
		"type":               "Ed25519VerificationKey2020",
		"controller":         "did:example:123",
		"publicKeyMultibase": "zHgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL",
	}

	// https://www.w3.org/TR/did-core/#example-did-document-with-many-different-key-types
	var exampleVerificationMethod = VerificationMethod{
		ID:         "did:example:123#key-0",
		Type:       "JsonWebKey2020",
		Controller: "did:example:123",
		PublicKeyJWK: &crypto.PublicKeyJWK{
			KTY: "OKP",
			CRV: "Ed25519",
			X:   "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
		},
	}

	// https://www.w3.org/TR/did-core/#example-key-agreement-property-containing-two-verification-methods
	var exampleKeyAgreementEntry = map[string]string{
		"id":                 "did:example:123#zC9ByQ8aJs8vrNXyDhPHHNNMSHPcaSgNpjjsBYpMMjsTdS",
		"type":               "X25519KeyAgreementKey2019",
		"controller":         "did:example:123",
		"publicKeyMultibase": "z9hFgmPVfmBZwRvFEyniQDBkz9LmV7gDEqytWyGZLmDXE",
	}

	builder := NewDIDDocumentBuilder()
	_, err := builder.Build()
	assert.NoError(t, err)
	assert.False(t, builder.IsEmpty())

	// default context should be set
	assert.NotEmpty(t, builder.Context)

	// set context of a bad type
	err = builder.AddContext(4)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed context")

	// correct context
	err = builder.AddContext("https://w3id.org/did/v1")
	assert.NoError(t, err)

	// there is a default id
	assert.NotEmpty(t, builder.ID)

	// set id
	id := "test-id"
	err = builder.SetID(id)
	assert.NoError(t, err)

	// set also known as
	err = builder.SetAlsoKnownAs("aka")
	assert.NoError(t, err)

	// TODO: Fix test methods
	// set controller
	err = builder.SetController("controller")
	assert.NoError(t, err)

	// valid type as a []string
	err = builder.AddAuthentication(exampleAuthenticationEntry)
	assert.NoError(t, err)

	// set issuer as a string
	err = builder.AddAssertionMethod(exampleAssertionEntry)
	assert.NoError(t, err)

	// set issuer as a string
	err = builder.AddKeyAgreement(exampleKeyAgreementEntry)
	assert.NoError(t, err)

	err = builder.AddCapabilityInvocation(exampleCapabilityInvocationEntry)
	assert.NoError(t, err)

	err = builder.AddCapabilityDelgation(exampleCapabilityDelegationEntry)
	assert.NoError(t, err)

	err = builder.AddVerificationMethod(exampleVerificationMethod)
	assert.NoError(t, err)

	err = builder.AddService(
		Service{
			ID:              "did:example:123#linked-domain",
			Type:            "LinkedDomains",
			ServiceEndpoint: "https://bar.example.com",
		})

	assert.NoError(t, err)

	// build it and verify some values
	cred, err := builder.Build()
	assert.NoError(t, err)
	assert.NotEmpty(t, cred)
	assert.Equal(t, id, cred.ID)
}
