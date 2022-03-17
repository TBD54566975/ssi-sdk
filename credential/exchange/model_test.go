package exchange

import (
	"github.com/gobuffalo/packr/v2"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	DefinitionVector1            string = "pe-definition-example-1.json"
	DefinitionVector2            string = "pe-definition-example-2.json"
	DefinitionVector3            string = "pe-definition-example-3.json"
	InputDescriptorsVector1      string = "pe-input-descriptors-example-1.json"
	InputDescriptorsVector2      string = "pe-input-descriptors-example-2.json"
	SubmissionVector1            string = "pe-submission-example-1.json"
	SubmissionVector2            string = "pe-submission-example-2.json"
	SubmissionRequirementVector1 string = "pe-submission-requirement-example-1.json"
	SubmissionRequirementVector2 string = "pe-submission-requirement-example-2.json"
)

var (
	peBox     = packr.New("Presentation Exchange Test Vectors", "../test_vectors")
	peVectors = []string{DefinitionVector1, DefinitionVector2, DefinitionVector3,
		InputDescriptorsVector1, InputDescriptorsVector2, SubmissionVector1, SubmissionVector2,
		SubmissionRequirementVector1, SubmissionRequirementVector2}
)

// Round trip de/serialize to test our object models

func TestPresentationDefinition(t *testing.T) {
	// examples here https://identity.foundation/presentation-exchange/#presentation-definition
	t.Run("Definition Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(DefinitionVector1)
		assert.NoError(tt, err)

		var def PresentationDefinition
		err = json.Unmarshal([]byte(vector), &def)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, def)

		roundTripBytes, err := json.Marshal(def)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Definition Vector 2", func(tt *testing.T) {
		vector, err := getTestVector(DefinitionVector2)
		assert.NoError(tt, err)

		var def PresentationDefinition
		err = json.Unmarshal([]byte(vector), &def)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, def)

		roundTripBytes, err := json.Marshal(def)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Definition Vector 3", func(tt *testing.T) {
		vector, err := getTestVector(DefinitionVector3)
		assert.NoError(tt, err)

		var def PresentationDefinition
		err = json.Unmarshal([]byte(vector), &def)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, def)

		roundTripBytes, err := json.Marshal(def)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Input Descriptors Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(InputDescriptorsVector1)
		assert.NoError(tt, err)

		var def PresentationDefinition
		err = json.Unmarshal([]byte(vector), &def)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, def)

		roundTripBytes, err := json.Marshal(def)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Input Descriptors Vector 2", func(tt *testing.T) {
		vector, err := getTestVector(InputDescriptorsVector2)
		assert.NoError(tt, err)

		var def PresentationDefinition
		err = json.Unmarshal([]byte(vector), &def)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, def)

		roundTripBytes, err := json.Marshal(def)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Submission Requirements Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(SubmissionRequirementVector1)
		assert.NoError(tt, err)

		var def PresentationDefinition
		err = json.Unmarshal([]byte(vector), &def)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, def)

		roundTripBytes, err := json.Marshal(def)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Submission Requirements Vector 2", func(tt *testing.T) {
		vector, err := getTestVector(SubmissionRequirementVector1)
		assert.NoError(tt, err)

		var def PresentationDefinition
		err = json.Unmarshal([]byte(vector), &def)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, def)

		roundTripBytes, err := json.Marshal(def)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func TestPresentationSubmission(t *testing.T) {
	// examples here and after https://identity.foundation/presentation-exchange/#basic-presentation-submission-object-1
}

func getTestVector(fileName string) (string, error) {
	return peBox.FindString(fileName)
}
