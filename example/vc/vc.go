// This is a simple application which creates a Verifiable Credential.
// It can do so via a builder or directly initializing a VerifiedCredentials struct from the credentials package.
package main

import (
	"fmt"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/example"
	"github.com/TBD54566975/ssi-sdk/util"
)

func main() {
	// Make a Verifiable Credential using the VC data type directly. Alternatively, use the builder
	// A VC is set of tamper-evident claims and metadata that cryptographically prove who issued it
	// Building a VC means using the CredentialBuilder as part of the credentials package in the ssk-sdk.
	// VerifiableCredential is the verifiable credential model outlined in the
	// vc-data-model spec https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#basic-concept
	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := "https://example.edu/issuers/565049"
	knownIssuanceDate := "2010-01-01T19:23:24Z"
	knownSubject := map[string]any{
		"id": "did:example:ebfeb1f712ebc6f1c276e12ec21", // did:<method-name>:<method-specific-id>
		"alumniOf": map[string]any{ // claims are here
			"id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
			"name": []any{
				map[string]any{"value": "Example University",
					"lang": "en",
				}, map[string]any{
					"value": "Exemple d'Université",
					"lang":  "fr",
				},
			},
		},
	}

	// For more information on VC object, go to:
	// https://github.com/TBD54566975/ssi-sdk/blob/main/credential/model.go
	vc := credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	// Make sure the VC is valid
	if err := vc.IsValid(); err != nil {
		example.HandleExampleError(err, "Verifiable Credential is not valid")
	}

	if dat, err := util.PrettyJSON(vc); err != nil {
		example.HandleExampleError(err, "failed to marshal DID document")
	} else {
		fmt.Printf("Created Verifiable Credential:\n %s", string(dat))
	}
}
