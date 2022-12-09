package schema

import (
	"embed"
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
	defaultSchemaURL = "schema.json"
)

var (
	//go:embed known_schemas
	knownSchemas embed.FS
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

// IsJSONValidAgainstSchema validates a piece of JSON against a schema, returning an error if it is not valid
func IsJSONValidAgainstSchema(json, schema string) error {
	if !IsValidJSON(json) {
		return errors.New("json input is not valid json")
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
	jsonInterface, err := util.ToJSONInterface(json)
	if err != nil {
		return errors.Wrap(err, "could not convert json to interface")
	}
	return jsonSchema.Validate(jsonInterface)
}

// IsJSONValidAgainstSchemaGeneric validates a piece of JSON as an interface{} against a schema,
// returning an error if it is not valid
func IsJSONValidAgainstSchemaGeneric(json interface{}, schema string) error {
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
	return jsonSchema.Validate(json)
}

func GetKnownSchema(fileName string) (string, error) {
	b, err := knownSchemas.ReadFile("known_schemas/" + fileName)
	return string(b), err
}
