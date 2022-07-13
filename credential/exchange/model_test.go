package exchange

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
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
	//go:embed testdata
	testVectors embed.FS
)

// Round trip de/serialize to test our object models

func TestPresentationDefinition(t *testing.T) {
	// example here https://identity.foundation/presentation-exchange/#presentation-definition

	t.Run("Definition Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(DefinitionVector1)
		assert.NoError(tt, err)

		var def PresentationDefinition
		err = json.Unmarshal([]byte(vector), &def)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, def)

		assert.NoError(tt, def.IsValid())

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

		assert.NoError(tt, def.IsValid())

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

		assert.NoError(tt, def.IsValid())

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

		assert.NoError(tt, def.IsValid())

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

		assert.NoError(tt, def.IsValid())

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

		assert.NoError(tt, def.IsValid())

		roundTripBytes, err := json.Marshal(def)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Submission Requirements Vector 2", func(tt *testing.T) {
		vector, err := getTestVector(SubmissionRequirementVector2)
		assert.NoError(tt, err)

		var def PresentationDefinition
		err = json.Unmarshal([]byte(vector), &def)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, def)

		assert.NoError(tt, def.IsValid())

		roundTripBytes, err := json.Marshal(def)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func TestPresentationSubmission(t *testing.T) {
	// example here and after https://identity.foundation/presentation-exchange/#basic-presentation-submission-object-1

	t.Run("Presentation Submission Vector 1", func(tt *testing.T) {
		vector, err := getTestVector(SubmissionVector1)
		assert.NoError(tt, err)

		var sub PresentationSubmission
		err = json.Unmarshal([]byte(vector), &sub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, sub)

		assert.NoError(tt, sub.IsValid())

		roundTripBytes, err := json.Marshal(sub)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})

	t.Run("Presentation Submission Vector 2", func(tt *testing.T) {
		vector, err := getTestVector(SubmissionVector2)
		assert.NoError(tt, err)

		var sub PresentationSubmission
		err = json.Unmarshal([]byte(vector), &sub)
		assert.NoError(tt, err)
		assert.NotEmpty(tt, sub)

		assert.NoError(tt, sub.IsValid())

		roundTripBytes, err := json.Marshal(sub)
		assert.NoError(tt, err)
		assert.JSONEq(tt, vector, string(roundTripBytes))
	})
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
