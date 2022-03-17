package manifest

import (
	"github.com/gobuffalo/packr/v2"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	Manifest
)

var (
	manifestBox = packr.New("Credential Manifest Test Vectors", "../test_vectors")
)

// Round trip de/serialize to test our object models

func TestCredentialManifest(t *testing.T) {
	t.Run("Presentation Submission Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(SubmissionVector1)
		assert.NoError(tt, err)

		var sub PresentationSubmission
		err = json.Unmarshal([]byte(vector), &sub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, sub)

		roundTripBytes, err := json.Marshal(sub)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func getTestVector(fileName string) (string, error) {
	return manifestBox.FindString(fileName)
}
