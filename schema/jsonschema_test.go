package schema

import (
	"github.com/gobuffalo/packr/v2"
	"testing"

	"github.com/goccy/go-json"

	"github.com/stretchr/testify/assert"
)

const (
	JSONSchemaTestVector1 string = "address.json"
	JSONSchemaTestVector2 string = "person.json"
)

var (
	box                   = packr.New("JSON Schema Test Vectors", "./test_vectors")
	jsonSchemaTestVectors = []string{JSONSchemaTestVector1, JSONSchemaTestVector2}
)

// Before running, you'll need to execute `mage packr`
func TestJSONSchemaVectors(t *testing.T) {
	for _, tv := range jsonSchemaTestVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		assert.True(t, IsValidJSON(gotTestVector))
		assert.NoError(t, IsValidJSONSchema(gotTestVector))
	}
}

func TestJSONSchemaValidation(t *testing.T) {
	t.Run("Test Invalid JSON Schema", func(tt *testing.T) {
		err := IsValidJSONSchema("bad")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "input is not valid json")

		badSchema := `{
  "$id": "https://example.com/person.schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Person",
  "type": "object",
  "properties": {
    "firstName": {
      "type": "string",
      "description": "The person's first name."
    },
    "lastName": {
      "type": "string",
      "description": "The person's last name."
    },
    "required": ["middleName"]
  },
  "additionalProperties": false
}`
		err = IsValidJSONSchema(badSchema)
		assert.Error(tt, err)
	})

	t.Run("Test Valid Address JSON Schema", func(tt *testing.T) {
		addressJSONSchema, err := getTestVector(JSONSchemaTestVector1)
		assert.NoError(tt, err)

		addressData := map[string]interface{}{
			"street-address": "1455 Market St.",
			"city":           "San Francisco",
			"state":          "California",
			"postal-code":    "94103",
		}

		addressDataBytes, err := json.Marshal(addressData)
		assert.NoError(tt, err)

		addressDataJSON := string(addressDataBytes)
		assert.True(tt, IsValidJSON(addressDataJSON))

		assert.NoError(tt, IsJSONValidAgainstSchema(addressDataJSON, addressJSONSchema))
	})

	t.Run("Test Invalid Address JSON Schema", func(tt *testing.T) {
		addressJSONSchema, err := getTestVector(JSONSchemaTestVector1)
		assert.NoError(tt, err)

		// Missing required field
		addressData := map[string]interface{}{
			"street-address": "1455 Market St.",
			"city":           "San Francisco",
			"state":          "California",
		}

		addressDataBytes, err := json.Marshal(addressData)
		assert.NoError(tt, err)

		addressDataJSON := string(addressDataBytes)
		assert.True(tt, IsValidJSON(addressDataJSON))

		err = IsJSONValidAgainstSchema(addressDataJSON, addressJSONSchema)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "postal-code is required")
	})

	t.Run("Test Valid Person JSON Schema", func(tt *testing.T) {
		personJSONSchema, err := getTestVector(JSONSchemaTestVector2)
		assert.NoError(tt, err)

		// Additional field
		personData := map[string]interface{}{
			"firstName": "Satoshi",
			"lastName":  "Nakamoto",
		}

		personDataBytes, err := json.Marshal(personData)
		assert.NoError(tt, err)

		personDataJSON := string(personDataBytes)
		assert.True(tt, IsValidJSON(personDataJSON))

		assert.NoError(tt, IsJSONValidAgainstSchema(personDataJSON, personJSONSchema))
	})

	t.Run("Test Invalid Person JSON Schema", func(tt *testing.T) {
		personJSONSchema, err := getTestVector(JSONSchemaTestVector2)
		assert.NoError(tt, err)

		// Additional field
		personData := map[string]interface{}{
			"firstName":  "Satoshi",
			"middleName": "Coin",
			"lastName":   "Nakamoto",
			"age":        "42",
		}

		personDataBytes, err := json.Marshal(personData)
		assert.NoError(tt, err)

		personDataJSON := string(personDataBytes)
		assert.True(tt, IsValidJSON(personDataJSON))

		err = IsJSONValidAgainstSchema(personDataJSON, personJSONSchema)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "Additional property middleName is not allowed")
	})
}

func TestLoadJSONSchema(t *testing.T) {
	schemaString := `{
  "$id": "https://example.com/geographical-location.schema.json",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Longitude and Latitude Values",
  "description": "A geographical coordinate.",
  "required": [ "latitude", "longitude" ],
  "type": "object",
  "properties": {
    "latitude": {
      "type": "number",
      "minimum": -90,
      "maximum": 90
    },
    "longitude": {
      "type": "number",
      "minimum": -180,
      "maximum": 180
    }
  }
}`

	assert.NoError(t, IsValidJSONSchema(schemaString))

	latLong := map[string]interface{}{
		"latitude":  1,
		"longitude": 1,
	}

	latLongBytes, err := json.Marshal(latLong)
	assert.NoError(t, err)

	latLongJSON := string(latLongBytes)
	assert.True(t, IsValidJSON(latLongJSON))

	err = IsJSONValidAgainstSchema(latLongJSON, schemaString)
	assert.NoError(t, err)
}

func getTestVector(fileName string) (string, error) {
	return box.FindString(fileName)
}
