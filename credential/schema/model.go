package schema

import "fmt"

const (
	// VCJSONSchemaType https://w3c-ccg.github.io/vc-json-schemas/v2/index.html#credential_schema_definition_metadata
	VCJSONSchemaType string = "https://w3c-ccg.github.io/vc-json-schemas/schema/2.0/schema.json"
)

type JSONSchema map[string]interface{}

// VCJSONSchema is the model representing the
// credential json schema specification https://w3c-ccg.github.io/vc-json-schemas/v2/index.html#credential_schema_definition
type VCJSONSchema struct {
	Type     string     `json:"type"`
	Version  string     `json:"version"`
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Author   string     `json:"author"`
	Authored string     `json:"authored"`
	Schema   JSONSchema `json:"schema"`
}

func (vcs VCJSONSchema) GetProperty(propertyName string) (any, error) {
	got, ok := vcs.Schema[propertyName]
	if !ok {
		return "", fmt.Errorf("property<%s> not found in schema<%s>", propertyName, vcs.ID)
	}
	return got, nil
}
