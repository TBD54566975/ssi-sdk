package schema

import (
	"fmt"

	"github.com/goccy/go-json"
)

const (
	// JSONSchemaCredentialType https://www.w3.org/TR/vc-json-schema/#jsonschemacredential
	JSONSchemaCredentialType VCJSONSchemaType = "JsonSchemaCredential"
	// JSONSchemaType https://www.w3.org/TR/vc-json-schema/#jsonschema
	JSONSchemaType VCJSONSchemaType = "JsonSchema"
	TypeProperty   string           = "type"

	// Known CredentialSchema property values for JsonSchemaCredential

	JSONSchemaCredentialSchemaID  = "https://www.w3.org/2022/credentials/v2/json-schema-credential-schema.json"
	JSONSchemaCredentialDigestSRI = "sha384-S57yQDg1MTzF56Oi9DbSQ14u7jBy0RDdx0YbeV7shwhCS88G8SCXeFq82PafhCrW"

	Draft202012 JSONSchemaVersion = "https://json-schema.org/draft/2020-12/schema"
	Draft201909 JSONSchemaVersion = "https://json-schema.org/draft/2019-09/schema"
	Draft7      JSONSchemaVersion = "https://json-schema.org/draft-07/schema#"

	// Known JSON Schema properties

	JSONSchemaIDProperty           = "$id"
	JSONSchemaAdditionalIDProperty = "id"
	JSONSchemaSchemaProperty       = "$schema"
	JSONSchemaNameProperty         = "name"
	JSONSchemaDescriptionProperty  = "description"
)

type (
	VCJSONSchemaType  string
	JSONSchemaVersion string
	VCJSONSchema      map[string]any
	JSONSchema        map[string]any
)

func (s VCJSONSchemaType) String() string {
	return string(s)
}

func (s JSONSchemaVersion) String() string {
	return string(s)
}

func (s VCJSONSchema) String() string {
	schemaBytes, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(schemaBytes)
}

func (s JSONSchema) String() string {
	schemaBytes, err := json.Marshal(s)
	if err != nil {
		return ""
	}
	return string(schemaBytes)
}

// GetProperty returns the value of a property in the schema
func (s JSONSchema) GetProperty(propertyName string) (any, error) {
	got, ok := s[propertyName]
	if !ok {
		return "", fmt.Errorf("property<%s> not found in schema<%s>", propertyName, s[JSONSchemaIDProperty])
	}
	return got, nil
}

func (s JSONSchema) ID() string {
	if id, ok := s[JSONSchemaIDProperty].(string); ok {
		return id
	}
	if id, ok := s[JSONSchemaAdditionalIDProperty].(string); ok {
		return id
	}
	return ""
}

func (s JSONSchema) Schema() string {
	if schema, ok := s[JSONSchemaSchemaProperty].(string); ok {
		return schema
	}
	return ""
}

func (s JSONSchema) Name() string {
	if name, ok := s[JSONSchemaNameProperty].(string); ok {
		return name
	}
	return ""
}

func (s JSONSchema) Description() string {
	if description, ok := s[JSONSchemaDescriptionProperty].(string); ok {
		return description
	}
	return ""
}

// IsSupportedJSONSchemaVersion returns true if the given version is supported
func IsSupportedJSONSchemaVersion(version string) bool {
	for _, v := range GetSupportedJSONSchemaVersions() {
		if v.String() == version {
			return true
		}
	}
	return false
}

// GetSupportedJSONSchemaVersions returns the supported JSON Schema versions
func GetSupportedJSONSchemaVersions() []JSONSchemaVersion {
	return []JSONSchemaVersion{Draft7, Draft201909, Draft202012}
}

// IsSupportedVCJSONSchemaType returns true if the given type is supported
func IsSupportedVCJSONSchemaType(t string) bool {
	for _, v := range GetSupportedVCJSONSchemaTypes() {
		if v.String() == t {
			return true
		}
	}
	return false
}

// GetSupportedVCJSONSchemaTypes returns the supported VC JSON Schema types
func GetSupportedVCJSONSchemaTypes() []VCJSONSchemaType {
	return []VCJSONSchemaType{JSONSchemaCredentialType, JSONSchemaType}
}
