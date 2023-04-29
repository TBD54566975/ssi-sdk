package pkg

import (
	"fmt"
	"time"

	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/goccy/go-json"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/example"
	"github.com/sirupsen/logrus"
)

// BuildExampleUniversityVC Makes a Verifiable Credential using the VC data type directly.
// Alternatively, use the builder. A VC is set of tamper-evident claims and metadata that cryptographically proves
// who issued it.  Building a VC means using the CredentialBuilder as part of the credentials package in the ssk-sdk.
// VerifiableCredential is the verifiable credential model outlined in the vc-data-model spec:
// https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#basic-concept
func BuildExampleUniversityVC(signer jwx.JWTSigner, universityDID, recipientDID string) (credID string, cred string, err error) {
	knownContext := []string{"https://www.w3.org/2018/credentials/v1",
		"https://www.w3.org/2018/credentials/examples/v1"} // JSON-LD context statement
	knownID := "http://example.edu/credentials/1872"
	knownType := []string{"VerifiableCredential", "AlumniCredential"}
	knownIssuer := universityDID
	knownIssuanceDate := time.Now().Format(time.RFC3339)
	knownSubject := map[string]any{
		"id": recipientDID, // did:<method-name>:<method-specific-id>
		"alumniOf": map[string]any{ // claims are here
			"id": recipientDID,
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
	knownCred := credential.VerifiableCredential{
		Context:           knownContext,
		ID:                knownID,
		Type:              knownType,
		Issuer:            knownIssuer,
		IssuanceDate:      knownIssuanceDate,
		CredentialSubject: knownSubject,
	}

	if err := knownCred.IsValid(); err != nil {
		return "", "", err
	}

	dat, err := json.Marshal(knownCred)
	if err != nil {
		return "", "", err
	}
	logrus.Debug(string(dat))

	// sign the credential as a JWT
	signedCred, err := credential.SignVerifiableCredentialJWT(signer, knownCred)
	if err != nil {
		return "", "", err
	}
	cred = string(signedCred)
	_, credToken, _, err := credential.ParseVerifiableCredentialFromJWT(string(signedCred))
	if err != nil {
		return "", "", err
	}
	credID = credToken.JwtID()

	example.WriteNote(fmt.Sprintf("VC issued from %s to %s", universityDID, recipientDID))

	return credID, cred, nil
}
