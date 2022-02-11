package schema

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/gobuffalo/packr/v2"
)

const (
	TestVector1 string = "address.json"
	TestVector2 string = "person.json"
)

var (
	box         = packr.New("JSON Schema Test Vectors", "./test_vectors")
	testVectors = []string{TestVector1, TestVector2}
)

// Before running, you'll need to execute `mage packr`
func TestJSONSchemaVectors(t *testing.T) {
	for _, tv := range testVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		assert.True(t, IsValidJSON(gotTestVector))
		assert.NoError(t, IsValidJSONSchema(gotTestVector))
	}
}

func TestJSONSchemaValidation(t *testing.T) {
	t.Run("Test Valid Address JSON Schema", func(t *testing.T) {
		addressJSONSchema, err := getTestVector(TestVector1)
		assert.NoError(t, err)

		addressData := map[string]interface{}{
			"street-address": "1455 Market St.",
			"city":           "San Francisco",
			"state":          "California",
			"postal-code":    "94103",
		}

		addressDataBytes, err := json.Marshal(addressData)
		assert.NoError(t, err)

		addressDataJSON := string(addressDataBytes)
		assert.True(t, IsValidJSON(addressDataJSON))

		assert.NoError(t, IsJSONValidAgainstSchema(addressDataJSON, addressJSONSchema))
	})

	t.Run("Test Invalid Address JSON Schema", func(t *testing.T) {
		addressJSONSchema, err := getTestVector(TestVector1)
		assert.NoError(t, err)

		// Missing required field
		addressData := map[string]interface{}{
			"street-address": "1455 Market St.",
			"city":           "San Francisco",
			"state":          "California",
		}

		addressDataBytes, err := json.Marshal(addressData)
		assert.NoError(t, err)

		addressDataJSON := string(addressDataBytes)
		assert.True(t, IsValidJSON(addressDataJSON))

		err = IsJSONValidAgainstSchema(addressDataJSON, addressJSONSchema)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "postal-code is required")
	})

	t.Run("Test Valid Person JSON Schema", func(t *testing.T) {
		personJSONSchema, err := getTestVector(TestVector2)
		assert.NoError(t, err)

		// Additional field
		personData := map[string]interface{}{
			"firstName": "Satoshi",
			"lastName":  "Nakamoto",
		}

		personDataBytes, err := json.Marshal(personData)
		assert.NoError(t, err)

		personDataJSON := string(personDataBytes)
		assert.True(t, IsValidJSON(personDataJSON))

		assert.NoError(t, IsJSONValidAgainstSchema(personDataJSON, personJSONSchema))
	})

	t.Run("Test Invalid Person JSON Schema", func(t *testing.T) {
		personJSONSchema, err := getTestVector(TestVector2)
		assert.NoError(t, err)

		// Additional field
		personData := map[string]interface{}{
			"firstName":  "Satoshi",
			"middleName": "Coin",
			"lastName":   "Nakamoto",
			"age":        "42",
		}

		personDataBytes, err := json.Marshal(personData)
		assert.NoError(t, err)

		personDataJSON := string(personDataBytes)
		assert.True(t, IsValidJSON(personDataJSON))

		err = IsJSONValidAgainstSchema(personDataJSON, personJSONSchema)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Additional property middleName is not allowed")
	})
}

func getTestVector(fileName string) (string, error) {
	return box.FindString(fileName)
}
