package manifest

import (
	"embed"
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/cryptosuite"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

const (
	ManifestVector1    string = "cm-manifest-example-1.json"
	ManifestVector2    string = "cm-manifest-example-2.json"
	ApplicationVector1 string = "cm-application-example-1.json"
	ResponseVector1    string = "cm-response-example-1.json"
	ResponseVector2    string = "cm-response-example-2.json"
)

var (
	//go:embed testdata
	testVectors embed.FS
)

// Round trip de/serialize to test our object models, and check validity

func TestCredentialManifest(t *testing.T) {
	// examples here https://identity.foundation/credential-manifest/#credential-response

	t.Run("Credential Manifest Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(ManifestVector1)
		assert.NoError(tt, err)

		var man CredentialManifest
		err = json.Unmarshal([]byte(vector), &man)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, man)

		assert.NoError(tt, man.IsValid())

		roundTripBytes, err := json.Marshal(man)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Credential Manifest Vector 2", func(tt *testing.T) {
		vector, err := getTestVector(ManifestVector2)
		assert.NoError(tt, err)

		type outputDescriptors struct {
			OutputDescriptors []OutputDescriptor `json:"output_descriptors" validate:"required"`
		}

		var od outputDescriptors
		err = json.Unmarshal([]byte(vector), &od)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, od)

		for _, d := range od.OutputDescriptors {
			assert.NoError(tt, d.IsValid())
		}

		roundTripBytes, err := json.Marshal(od)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func TestCredentialApplication(t *testing.T) {
	// example here https://identity.foundation/credential-manifest/#credential-application---simple-example

	t.Run("Credential Application Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(ApplicationVector1)
		assert.NoError(tt, err)

		var app CredentialApplication
		err = json.Unmarshal([]byte(vector), &app)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, app)

		assert.NoError(tt, app.IsValid())

		roundTripBytes, err := json.Marshal(app)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func TestCredentialResponse(t *testing.T) {
	// example here https://identity.foundation/credential-manifest/#credential-response

	t.Run("Credential Response - Fulfillment Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(ResponseVector1)
		assert.NoError(tt, err)

		var response CredentialResponse
		err = json.Unmarshal([]byte(vector), &response)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, response)

		assert.NoError(tt, response.IsValid())

		roundTripBytes, err := json.Marshal(response)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Credential Response - Denial Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(ResponseVector2)
		assert.NoError(tt, err)

		var response CredentialResponse
		err = json.Unmarshal([]byte(vector), &response)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, response)

		assert.NoError(tt, response.IsValid())

		roundTripBytes, err := json.Marshal(response)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func TestIsValidPair(t *testing.T) {

	t.Run("Credential Application and Credential Manifest Pair Valid", func(tt *testing.T) {
		credAppJson, err := getTestVector(ApplicationVector1)
		assert.NoError(tt, err)

		var app CredentialApplication
		err = json.Unmarshal([]byte(credAppJson), &app)

		assert.NoError(tt, err)
		assert.NotEmpty(tt, app)
		assert.NoError(tt, app.IsValid())

		manifestJson, err := getTestVector(ManifestVector1)

		assert.NoError(tt, err)

		var man CredentialManifest
		err = json.Unmarshal([]byte(manifestJson), &man)

		assert.NoError(tt, err)
		assert.NotEmpty(tt, man)
		assert.NoError(tt, man.IsValid())

		err = IsValidPair(man, app)

		assert.NoError(tt, err)
	})

	t.Run("Credential Application and Credential Manifest Pair Full Test", func(tt *testing.T) {

		manifestJson, err := getTestVector(ManifestVector1)

		assert.NoError(tt, err)

		var cm CredentialManifest
		err = json.Unmarshal([]byte(manifestJson), &cm)

		assert.NoError(tt, err)
		assert.NotEmpty(tt, cm)
		assert.NoError(tt, cm.IsValid())

		credAppJson, err := getTestVector(ApplicationVector1)
		assert.NoError(tt, err)

		var ca CredentialApplication
		err = json.Unmarshal([]byte(credAppJson), &ca)

		assert.NoError(tt, err)
		assert.NotEmpty(tt, ca)
		assert.NoError(tt, ca.IsValid())

		ca.ManifestID = "bad-id"

		err = IsValidPair(cm, ca)
		assert.Contains(t, err.Error(), "the credential application's manifest id must be equal to the credential manifest's id")

		// reset
		ca.ManifestID = cm.ID

		cm.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		ca.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		err = IsValidPair(cm, ca)
		assert.NoError(tt, err)

		cm.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
			LDP: &exchange.LDPType{ProofType: []cryptosuite.SignatureType{"sigtype"}},
		}

		ca.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		err = IsValidPair(cm, ca)
		assert.NoError(tt, err)

		cm.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		ca.Format = &exchange.ClaimFormat{
			LDP: &exchange.LDPType{ProofType: []cryptosuite.SignatureType{"sigtype"}},
		}

		err = IsValidPair(cm, ca)
		assert.Contains(t, err.Error(), "credential application's format must be a subset of the format property in the credential manifest")

		// reset
		ca.Format = &exchange.ClaimFormat{
			JWT: &exchange.JWTType{Alg: []crypto.SignatureAlgorithm{crypto.EdDSA}},
		}

		def := exchange.PresentationDefinition{
			ID: "test-id",
			InputDescriptors: []exchange.InputDescriptor{
				{
					ID: "id-1",
					Constraints: &exchange.Constraints{
						Fields: []exchange.Field{
							{
								Path:    []string{"$.vc.issuer", "$.issuer"},
								ID:      "issuer-input-descriptor",
								Purpose: "need to check the issuer",
							},
						},
					},
				},
			},
		}

		cm.PresentationDefinition = &def
		ca.PresentationSubmission.DefinitionID = "badid"

		err = IsValidPair(cm, ca)
		assert.Contains(t, err.Error(), "credential application's presentation submission's definition id does not match the credential manifest's id")

		ca.PresentationSubmission.DefinitionID = def.ID

		err = IsValidPair(cm, ca)
		assert.NoError(tt, err)

		ca.PresentationSubmission.DescriptorMap[0].Format = "badformat"

		err = IsValidPair(cm, ca)
		assert.Contains(t, err.Error(), "must be one of the following:")
	})
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
