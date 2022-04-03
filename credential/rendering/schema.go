package rendering

import (
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/gobuffalo/packr/v2"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

const (
	displayMappingObjectSchema        string = "wr-display-mapping-object.json"
	entityStylesSchema                string = "wr-entity-styles.json"
	labeledDisplayMappingObjectSchema string = "wr-labeled-display-mapping-object.json"
)

var (
	schemaBox = packr.New("Wallet Rendering JSON Schemas", "../known_schemas")
)

// IsValidEntityStyle validates an entity style descriptor against its known schema
func IsValidEntityStyle(esd EntityStyleDescriptor) error {
	jsonBytes, err := json.Marshal(esd)
	if err != nil {
		return errors.Wrap(err, "could not marshal entity style descriptor")
	}
	s, err := getKnownSchema(entityStylesSchema)
	if err != nil {
		return errors.Wrap(err, "could not get entity styles schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

// IsValidDisplayMappingObject validates a display mapping object against its known schema
func IsValidDisplayMappingObject(dmo DisplayMappingObject) error {
	jsonBytes, err := json.Marshal(dmo)
	if err != nil {
		return errors.Wrap(err, "could not marshal display mapping object")
	}
	s, err := getKnownSchema(displayMappingObjectSchema)
	if err != nil {
		return errors.Wrap(err, "could not get display mapping object schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

// IsValidLabeledDisplayMappingObject validates a labeled display mapping object against its known schema
func IsValidLabeledDisplayMappingObject(ldmo LabeledDisplayMappingObject) error {
	jsonBytes, err := json.Marshal(ldmo)
	if err != nil {
		return errors.Wrap(err, "could not marshal labeled display mapping object")
	}
	s, err := getKnownSchema(labeledDisplayMappingObjectSchema)
	if err != nil {
		return errors.Wrap(err, "could not get labeled display mapping object schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func getKnownSchema(fileName string) (string, error) {
	return schemaBox.FindString(fileName)
}
