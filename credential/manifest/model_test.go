package manifest

import (
	"github.com/gobuffalo/packr/v2"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	ManifestVector1     string = "cm-manifest-example-1.json"
	ManifestVector2     string = "cm-manifest-example-2.json"
	ApplicationVector1  string = "cm-application-example-1.json"
	FulfillmentExample1 string = "cm-fulfillment-example-1.json"
)

var (
	manifestBox = packr.New("Credential Manifest Test Vectors", "../test_vectors")
)

// Round trip de/serialize to test our object models, and check validity

func TestCredentialManifest(t *testing.T) {
	// examples here https://identity.foundation/credential-manifest/#credential-manifest---all-features-exercised

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

		roundTripBytes, err := json.Marshal(od)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func TestCredentialApplication(t *testing.T) {
	// examples here https://identity.foundation/credential-manifest/#credential-application---simple-example

	t.Run("Credential Application Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(ApplicationVector1)
		assert.NoError(tt, err)

		var app CredentialApplication
		err = json.Unmarshal([]byte(vector), &app)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, app)

		roundTripBytes, err := json.Marshal(app)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func TestCredentialFulfillment(t *testing.T) {
	// examples here https://identity.foundation/credential-manifest/#credential-fulfillment---simple-example

	t.Run("Credential Fulfillment Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(FulfillmentExample1)
		assert.NoError(tt, err)

		var fulfillment CredentialFulfillment
		err = json.Unmarshal([]byte(vector), &fulfillment)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, fulfillment)

		roundTripBytes, err := json.Marshal(fulfillment)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func getTestVector(fileName string) (string, error) {
	return manifestBox.FindString(fileName)
}
