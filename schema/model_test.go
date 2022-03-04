package schema

import (
	"testing"

	"github.com/goccy/go-json"

	"github.com/stretchr/testify/assert"
)

// Before running, you'll need to execute `mage packr`
// Round trip to and from our data model
func TestVCJSONSchema(t *testing.T) {
	schema, err := getTestVector(VCJSONTestVector1)
	assert.NoError(t, err)

	var vcJSONSchema VCJSONSchema
	err = json.Unmarshal([]byte(schema), &vcJSONSchema)
	assert.NoError(t, err)

	roundTripBytes, err := json.Marshal(vcJSONSchema)
	assert.NoError(t, err)

	roundTripString := string(roundTripBytes)
	assert.JSONEqf(t, schema, roundTripString, "error message %s")
}

func TestGetPropertyFromSchema(t *testing.T) {
	schema, err := getTestVector(VCJSONTestVector1)
	assert.NoError(t, err)

	var vcJSONSchema VCJSONSchema
	err = json.Unmarshal([]byte(schema), &vcJSONSchema)
	assert.NoError(t, err)

	property, err := vcJSONSchema.GetProperty("$id")
	assert.NoError(t, err)
	assert.EqualValues(t, "email-schema-1.0", property)
}
