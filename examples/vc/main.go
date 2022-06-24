// This is a very simple application which can create
// a Verifiable Credential.
// It can do so via a builder or directly
// initializing a VerifiedCredentials struct
// from the credentials package
package main

import (
	"encoding/json"

	"github.com/TBD54566975/ssi-sdk/credential"
)

// Build the credential with the builder
// VerifiableCredentialBuilder uses the builder
// pattern to construct a verifiable credential
// and is invoked via the Build function
// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/builder.go
// and https://github.com/TBD54566975/ssi-sdk/blob/main/credential/builder.go#L24
// for more information on specifically thee builder model
func buildVerifiableCredential() (*credential.VerifiableCredential, error) {

	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := "https://example.edu/issuers/565049"
	knownIssuanceDate := "2010-01-01T19:23:24Z"
	knownSubject := map[string]interface{}{
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21", //did:<method-name>:<method-specific-id>
		"alumniOf": map[string]interface{}{ // claims are here
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

	var err error
	builder := credential.NewVerifiableCredentialBuilder()

	err = builder.AddContext(knownContext)
	if err != nil {
		return nil, err
	}

	err = builder.SetID(knownID)
	if err != nil {
		return nil, err
	}

	err = builder.AddType(knownType)
	if err != nil {
		return nil, err
	}

	err = builder.SetIssuer(knownIssuer)
	if err != nil {
		return nil, err
	}

	err = builder.SetIssuanceDate(knownIssuanceDate)
	if err != nil {
		return nil, err
	}

	err = builder.SetCredentialSubject(knownSubject)
	if err != nil {
		return nil, err
	}

	cred, err := builder.Build()
	if err != nil {
		return nil, err
	}

	return cred, nil
}

// Make a Verifiable Credential
// using the VC data type directly.
// Alternatively, use the builder
// A VC is set of tamper-evident claims and metadata
// that cryptographically prove who issued it
// Building a VC means using the CredentialBuilder
// as part of the credentials package in the ssk-sdk.
// VerifiableCredential is the verifiable credential model outlined in the
// vc-data-model spec https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#basic-concept
func createVerifiableCredentials() (*credential.VerifiableCredential, error) {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := "https://example.edu/issuers/565049"
	knownIssuanceDate := "2010-01-01T19:23:24Z"
	knownSubject := map[string]interface{}{
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21", //did:<method-name>:<method-specific-id>
		"alumniOf": map[string]interface{}{ // claims are here
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

	// For more information on VC object, go to:
	// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/model.go
	knownCred := credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	err := knownCred.IsValid()
	if err != nil {
		return nil, err
	}

	return &knownCred, nil
}

func main() {

	vc, err := createVerifiableCredentials()
	if err != nil {
		panic(err)
	}

	dat, err := json.MarshalIndent(vc, "", "    ")
	if err != nil {
		panic(err)
	}
	print(string(dat))

}
