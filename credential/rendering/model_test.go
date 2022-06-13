package rendering

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
)

const (
	EntityStylesVector1              string = "wr-entity-styles-example-1.json"
	DisplayMappingPathVector1        string = "wr-display-mapping-path-example-1.json"
	DisplayMappingTextVector2        string = "wr-display-mapping-text-example-2.json"
	LabeledDisplayMappingPathVector1 string = "wr-labeled-display-mapping-path-example-1.json"
	LabeledDisplayMappingTextVector2 string = "wr-labeled-display-mapping-text-example-2.json"
)

var (
	//go:embed testdata
	testVectors embed.FS
)

func TestEntityStyleDescriptor(t *testing.T) {
	vector, err := getTestVector(EntityStylesVector1)
	assert.NoError(t, err)

	var esd EntityStyleDescriptor
	err = json.Unmarshal([]byte(vector), &esd)
	assert.NoError(t, err)
	assert.NotEmpty(t, esd)

	roundTripBytes, err := json.Marshal(esd)
	assert.NoError(t, err)
	assert.JSONEq(t, vector, string(roundTripBytes))
}

func TestDisplayMappingObject(t *testing.T) {
	t.Run("Path Vector", func(tt *testing.T) {
		vector, err := getTestVector(DisplayMappingPathVector1)
		assert.NoError(t, err)

		var dmo DisplayMappingObject
		err = json.Unmarshal([]byte(vector), &dmo)
		assert.NoError(t, err)
		assert.NotEmpty(t, dmo)

		assert.NoError(tt, dmo.IsValid())

		roundTripBytes, err := json.Marshal(dmo)
		assert.NoError(t, err)
		assert.JSONEq(t, vector, string(roundTripBytes))
	})

	t.Run("Text Vector", func(tt *testing.T) {
		vector, err := getTestVector(DisplayMappingTextVector2)
		assert.NoError(t, err)

		var dmo DisplayMappingObject
		err = json.Unmarshal([]byte(vector), &dmo)
		assert.NoError(t, err)
		assert.NotEmpty(t, dmo)

		assert.NoError(tt, dmo.IsValid())

		roundTripBytes, err := json.Marshal(dmo)
		assert.NoError(t, err)
		assert.JSONEq(t, vector, string(roundTripBytes))
	})
}

func TestLabeledDisplayMappingObject(t *testing.T) {
	t.Run("Path Vector", func(tt *testing.T) {
		vector, err := getTestVector(LabeledDisplayMappingPathVector1)
		assert.NoError(t, err)

		var ldmo LabeledDisplayMappingObject
		err = json.Unmarshal([]byte(vector), &ldmo)
		assert.NoError(t, err)
		assert.NotEmpty(t, ldmo)

		assert.NoError(tt, ldmo.IsValid())

		roundTripBytes, err := json.Marshal(ldmo)
		assert.NoError(t, err)
		assert.JSONEq(t, vector, string(roundTripBytes))
	})

	t.Run("Text Vector", func(tt *testing.T) {
		vector, err := getTestVector(LabeledDisplayMappingTextVector2)
		assert.NoError(t, err)

		var ldmo LabeledDisplayMappingObject
		err = json.Unmarshal([]byte(vector), &ldmo)
		assert.NoError(t, err)
		assert.NotEmpty(t, ldmo)

		assert.NoError(tt, ldmo.IsValid())

		roundTripBytes, err := json.Marshal(ldmo)
		assert.NoError(t, err)
		assert.JSONEq(t, vector, string(roundTripBytes))
	})
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
