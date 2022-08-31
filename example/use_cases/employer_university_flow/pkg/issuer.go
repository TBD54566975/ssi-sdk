package pkg

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/example"
	"github.com/sirupsen/logrus"
)

// Make a Verifiable Credential
// using the VC data type directly.
// Alternatively, use the builder
// A VC is set of tamper-evident claims and metadata
// that cryptographically prove who issued it
// Building a VC means using the CredentialBuilder
// as part of the credentials package in the ssk-sdk.
// VerifiableCredential is the verifiable credential model outlined in the
// vc-data-model spec https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#basic-concept
func BuildExampleUniversityVC(universityID, recipient string) (*credential.VerifiableCredential, error) {

	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := "https://example.edu/issuers/565049"
	knownIssuanceDate := time.Now().Format(time.RFC3339)
	knownSubject := map[string]interface{}{
		"id": universityID, //did:<method-name>:<method-specific-id>
		"alumniOf": map[string]interface{}{ // claims are here
			"id": recipient,
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
	// This is an embedded proof.
	// For more information
	// https://github.com/TBD54566975/ssi-sdk/blob/main/cryptosuite/jwssignaturesuite_test.go#L357
	// https://www.w3.org/TR/vc-data-model/#proofs-signatures

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

	if err := knownCred.IsValid(); err != nil {
		return nil, err
	}

	if dat, err := json.Marshal(knownCred); err == nil {
		logrus.Debug(string(dat))
	} else {
		return nil, err
	}

	example.WriteNote(fmt.Sprintf("VC issued from %s to %s", universityID, recipient))

	return &knownCred, nil
}
