package manifest

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

const (
	ManifestVector1    string = "cm-manifest-example-1.json"
	ManifestVector2    string = "cm-manifest-example-2.json"
	ApplicationVector1 string = "cm-application-example-1.json"
	CredentialVector1  string = "cm-credential-example-1.json"
	ResponseVector1    string = "cm-response-example-1.json"
	ResponseVector2    string = "cm-response-example-2.json"

	FullApplicationVector string = "full-application.json"
	FullCredentialVector  string = "full-credential.json"
	FullManifestVector    string = "full-manifest.json"
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

	t.Run("Credential Error - Denial Vector 1", func(tt *testing.T) {
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

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
