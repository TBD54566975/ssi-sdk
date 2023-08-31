package schema

import (
	"net/http"
	"time"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/santhosh-tekuri/jsonschema/v5"

	// imported for http loaders https://github.com/santhosh-tekuri/jsonschema/issues/92#issuecomment-1309794888
	"github.com/santhosh-tekuri/jsonschema/v5/httploader"
)

const (
	// defaultSchemaURL is a placeholder that's needed to load any schema
	defaultSchemaURL = "schema.json"
)

func init() {
	httploader.Client = &http.Client{
		Timeout: time.Second * 10,
	}
}

// IsValidJSONSchema returns an error if the schema is not a valid JSON Schema, nil otherwise
func IsValidJSONSchema(maybeSchema string) error {
	if !IsValidJSON(maybeSchema) {
		return errors.New("input is not valid json")
	}
	schema, err := jsonschema.CompileString(defaultSchemaURL, maybeSchema)
	if err != nil {
		return err
	}
	if schema == nil {
		return errors.New("schema could not be parsed")
	}
	return nil
}

// IsValidJSON checks if a string is valid json https://stackoverflow.com/a/36922225
func IsValidJSON(maybeJSON string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(maybeJSON), &js) == nil
}

// IsAnyValidAgainstJSONSchema validates a piece of JSON against a schema, returning an error if it is not valid
func IsAnyValidAgainstJSONSchema(data any, schema string) error {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return errors.Wrap(err, "marshaling data to JSON")
	}
	return IsValidAgainstJSONSchema(string(jsonBytes), schema)
}

// IsValidAgainstJSONSchema validates a piece of JSON against a schema, returning an error if it is not valid
func IsValidAgainstJSONSchema(data, schema string) error {
	if !IsValidJSON(data) {
		return errors.New("data is not valid json")
	}
	if !IsValidJSON(schema) {
		return errors.New("schema input is not valid json")
	}
	if err := IsValidJSONSchema(schema); err != nil {
		return errors.Wrap(err, "schema is not valid")
	}
	jsonSchema, err := jsonschema.CompileString(defaultSchemaURL, schema)
	if err != nil {
		return err
	}
	jsonInterface, err := util.ToJSONInterface(data)
	if err != nil {
		return errors.Wrap(err, "converting json to interface")
	}
	return jsonSchema.Validate(jsonInterface)
}
