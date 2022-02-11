package schema

import (
	"encoding/json"
	"net/url"

	"github.com/TBD54566975/did-sdk/util"

	"github.com/xeipuuv/gojsonschema"
)

// LoadJSONSchemaFromString loads a JSON schema from a string
func LoadJSONSchemaFromString(schema string) (interface{}, error) {
	loader := gojsonschema.NewStringLoader(schema)
	return loader.LoadJSON()
}

// LoadJSONSchemaFromRemote attempts to load a JSON Schema from a web resource
func LoadJSONSchemaFromRemote(maybeURL string) (interface{}, error) {
	if _, err := url.Parse(maybeURL); err != nil {
		return nil, err
	}
	loader := gojsonschema.NewReferenceLoader(maybeURL)
	return loader.LoadJSON()
}

// IsValidJSONSchema returns an error if the schema is not a valid JSON Schema, nil otherwise
func IsValidJSONSchema(maybeSchema string) error {
	loader := gojsonschema.NewStringLoader(maybeSchema)
	return gojsonschema.NewSchemaLoader().AddSchemas(loader)
}

// IsValidJSON checks if a string is valid json https://stackoverflow.com/a/36922225
func IsValidJSON(maybeJSON string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(maybeJSON), &js) == nil
}

// IsJSONValidAgainstSchema validates a piece of JSON against a schema, returning an error if it is not valid
func IsJSONValidAgainstSchema(json, schema string) error {
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
