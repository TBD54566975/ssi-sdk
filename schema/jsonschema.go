package schema

import (
	"github.com/goccy/go-json"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/util"

	"github.com/xeipuuv/gojsonschema"
)

// IsValidJSONSchema returns an error if the schema is not a valid JSON Schema, nil otherwise
func IsValidJSONSchema(maybeSchema string) error {
	if !IsValidJSON(maybeSchema) {
		return errors.New("input is not valid json")
	}
	stringLoader := gojsonschema.NewStringLoader(maybeSchema)
	schemaLoader := gojsonschema.NewSchemaLoader()
	schemaLoader.Validate = true
	schemaLoader.Draft = gojsonschema.Draft7
	_, err := schemaLoader.Compile(stringLoader)
	return err
}

// IsValidJSON checks if a string is valid json https://stackoverflow.com/a/36922225
func IsValidJSON(maybeJSON string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(maybeJSON), &js) == nil
}

// IsJSONValidAgainstSchema validates a piece of JSON against a schema, returning an error if it is not valid
func IsJSONValidAgainstSchema(json, schema string) error {
	if !IsValidJSON(json) {
		return errors.New("json input is not valid json")
	}
	if !IsValidJSON(schema) {
		return errors.New("schema input is not valid json")
	}
	jsonLoader := gojsonschema.NewStringLoader(json)
	schemaLoader := gojsonschema.NewStringLoader(schema)
	result, err := gojsonschema.Validate(schemaLoader, jsonLoader)
	if err != nil {
		return err
	}
	ae := util.NewAppendError()
	if !result.Valid() {
		for _, e := range result.Errors() {
			ae.AppendString(e.String())
		}
		err = ae.Error()
	}
	return err
}
