package schema

import (
	"fmt"
	"io"
	"net/http"
	"strings"
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

// LoadLocal is an interface that allows for loading of local schemas. It should be implemented by all
// packages that contain schemas which can be locally loaded.
type LoadLocal interface {
	LocalLoad() (map[string]string, error)
}

// LocalLoader is a struct that holds local schemas
type LocalLoader struct {
	localSchemas map[string]string
}

// NewLocalLoader returns a new LocalLoader without any schemas to be loaded locally
// Calling this method disables the ability to load schemas remotely over http and https
func NewLocalLoader() LocalLoader {
	localSchemas := make(map[string]string)
	jsonschema.Loaders["https"] = func(url string) (io.ReadCloser, error) {
		schema, ok := localSchemas[strings.TrimPrefix(url, "https://")]
		if !ok {
			return nil, fmt.Errorf("%q not found", url)
		}
		return io.NopCloser(strings.NewReader(schema)), nil
	}
	jsonschema.Loaders["http"] = func(url string) (io.ReadCloser, error) {
		schema, ok := localSchemas[strings.TrimPrefix(url, "http://")]
		if !ok {
			return nil, fmt.Errorf("%q not found", url)
		}
		return io.NopCloser(strings.NewReader(schema)), nil
	}
	return LocalLoader{localSchemas: localSchemas}
}

// AddLocalLoad adds a set of schemas from an implementer of `LoadLocal` to the local loader
func (l *LocalLoader) AddLocalLoad(ll LoadLocal) error {
	if l.localSchemas == nil {
		return errors.New("local loading is not instantiated")
	}
	kvs, err := ll.LocalLoad()
	if err != nil {
		return err
	}
	for schemaName, schemaValue := range kvs {
		if err = IsValidJSONSchema(schemaValue); err != nil {
			return errors.Wrapf(err, "schema %s is not valid", schemaName)
		}
		l.localSchemas[schemaName] = schemaValue
	}
	return nil
}

// // LoadAllLocal loads all local schemas from a known of LoadLocal implementers
// func LoadAllLocal() error {
// 	localLoader := NewLocalLoader()
// 	if err := localLoader.AddLocalLoad(new(exchange.PresentationExchangeSchema)); err != nil {
// 		return errors.Wrap(err, "could not load presentation exchange schema")
// 	}
// 	if err := localLoader.AddLocalLoad(new(manifest.CredentialManifestSchema)); err != nil {
// 		return errors.Wrap(err, "could not load credential manifest schema")
// 	}
// 	return nil
// }

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
