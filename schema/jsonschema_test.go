package schema

import (
	"embed"
	"testing"

	"github.com/goccy/go-json"

	"github.com/stretchr/testify/assert"
)

const (
	JSONSchemaTestVector1 string = "address.json"
	JSONSchemaTestVector2 string = "person.json"
)

var (
	//go:embed testdata
	testVectors           embed.FS
	jsonSchemaTestVectors = []string{JSONSchemaTestVector1, JSONSchemaTestVector2}
)

func TestJSONSchemaVectors(t *testing.T) {
	for _, tv := range jsonSchemaTestVectors {
		gotTestVector, err := getTestVector(tv)
		assert.NoError(t, err)

		assert.True(t, IsValidJSON(gotTestVector))
		assert.NoError(t, IsValidJSONSchema(gotTestVector))
	}
}

func TestIsValidJSON(t *testing.T) {
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

	t.Run("Test Valid JSON Schema", func(tt *testing.T) {
		addressJSONSchema, err := getTestVector(JSONSchemaTestVector1)
		assert.NoError(tt, err)

		err = IsValidJSONSchema(addressJSONSchema)
		assert.NoError(tt, err)
	})
}

func TestJSONSchemaValidation(t *testing.T) {
	t.Run("Test Invalid JSON Against Schema", func(tt *testing.T) {
		err := IsValidAgainstJSONSchema("bad", "bad")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "data is not valid json")
	})

	t.Run("Test Invalid JSON Schema", func(tt *testing.T) {
		addressData := map[string]any{
			"street-address": "1455 Market St.",
			"city":           "San Francisco",
			"state":          "California",
			"postal-code":    "94103",
		}

		addressDataBytes, err := json.Marshal(addressData)
		assert.NoError(tt, err)
		err = IsValidAgainstJSONSchema(string(addressDataBytes), "bad")
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "schema input is not valid json")
	})

	t.Run("Test Valid Address JSON Schema", func(tt *testing.T) {
		addressJSONSchema, err := getTestVector(JSONSchemaTestVector1)
		assert.NoError(tt, err)

		addressData := map[string]any{
			"street-address": "1455 Market St.",
			"city":           "San Francisco",
			"state":          "California",
			"postal-code":    "94103",
		}

		addressDataBytes, err := json.Marshal(addressData)
		assert.NoError(tt, err)

		addressDataJSON := string(addressDataBytes)
		assert.True(tt, IsValidJSON(addressDataJSON))

		assert.NoError(tt, IsValidAgainstJSONSchema(addressDataJSON, addressJSONSchema))
	})

	t.Run("Test Invalid Address JSON Schema", func(tt *testing.T) {
		addressJSONSchema, err := getTestVector(JSONSchemaTestVector1)
		assert.NoError(tt, err)

		// Missing required field
		addressData := map[string]any{
			"street-address": "1455 Market St.",
			"city":           "San Francisco",
			"state":          "California",
		}

		addressDataBytes, err := json.Marshal(addressData)
		assert.NoError(tt, err)

		addressDataJSON := string(addressDataBytes)
		assert.True(tt, IsValidJSON(addressDataJSON))

		err = IsValidAgainstJSONSchema(addressDataJSON, addressJSONSchema)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "missing properties: 'postal-code'")
	})

	t.Run("Test Valid Person JSON Schema", func(tt *testing.T) {
		personJSONSchema, err := getTestVector(JSONSchemaTestVector2)
		assert.NoError(tt, err)

		// Additional field
		personData := map[string]any{
			"firstName": "Satoshi",
			"lastName":  "Nakamoto",
		}

		personDataBytes, err := json.Marshal(personData)
		assert.NoError(tt, err)

		personDataJSON := string(personDataBytes)
		assert.True(tt, IsValidJSON(personDataJSON))

		assert.NoError(tt, IsValidAgainstJSONSchema(personDataJSON, personJSONSchema))
	})

	t.Run("Test Invalid Person JSON Schema", func(tt *testing.T) {
		personJSONSchema, err := getTestVector(JSONSchemaTestVector2)
		assert.NoError(tt, err)

		// Additional field
		personData := map[string]any{
			"firstName":  "Satoshi",
			"middleName": "Coin",
			"lastName":   "Nakamoto",
			"age":        42,
		}

		personDataBytes, err := json.Marshal(personData)
		assert.NoError(tt, err)

		personDataJSON := string(personDataBytes)
		assert.True(tt, IsValidJSON(personDataJSON))

		err = IsValidAgainstJSONSchema(personDataJSON, personJSONSchema)
		assert.Error(tt, err)
		assert.Contains(tt, err.Error(), "additionalProperties 'middleName' not allowed")
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

	latLong := map[string]any{
		"latitude":  1,
		"longitude": 1,
	}

	latLongBytes, err := json.Marshal(latLong)
	assert.NoError(t, err)

	latLongJSON := string(latLongBytes)
	assert.True(t, IsValidJSON(latLongJSON))

	err = IsValidAgainstJSONSchema(latLongJSON, schemaString)
	assert.NoError(t, err)
}

func getTestVector(fileName string) (string, error) {
	b, err := testVectors.ReadFile("testdata/" + fileName)
	return string(b), err
}
