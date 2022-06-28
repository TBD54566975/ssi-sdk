// This is a very simple application which can create
// a Verifiable Credential.
// It can do so via a builder or directly
// initializing a VerifiedCredentials struct
// from the credentials package
package main

import (
	"encoding/json"
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential"
)

// Build the credential with the builder
// VerifiableCredentialBuilder uses the builder
// pattern to construct a verifiable credential
// and is invoked via the Build function
// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/builder.go
// and https://github.com/TBD54566975/ssi-sdk/blob/main/credential/builder.go#L24
// for more information on specifically thee builder model
func buildVerifiableCredential() (cred *credential.VerifiableCredential, err error) {

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

	builder := credential.NewVerifiableCredentialBuilder()

	if err = builder.AddContext(knownContext); err != nil {
		return
	}

	if err = builder.SetID(knownID); err != nil {
		return
	}

	if err = builder.AddType(knownType); err != nil {
		return
	}

	if err = builder.SetIssuer(knownIssuer); err != nil {
		return
	}

	if err = builder.SetIssuanceDate(knownIssuanceDate); err != nil {
		return
	}

	if err = builder.SetCredentialSubject(knownSubject); err != nil {
		return
	}

	return builder.Build()
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

	fmt.Printf("Created Verifiable Credential:\n %s", string(dat))
}
