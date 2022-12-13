package rendering

import (
	"embed"

	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

var (
	//go:embed known_schemas
	knownSchemas embed.FS
)

type WalletRenderingSchema string

func (w WalletRenderingSchema) String() string {
	return string(w)
}

const (
	DisplayMappingObjectSchema        WalletRenderingSchema = "wr-display-mapping-object.json"
	EntityStylesSchema                WalletRenderingSchema = "wr-entity-styles.json"
	LabeledDisplayMappingObjectSchema WalletRenderingSchema = "wr-labeled-display-mapping-object.json"
)

// IsValidEntityStyle validates an entity style descriptor against its known schema
func IsValidEntityStyle(esd EntityStyleDescriptor) error {
	jsonBytes, err := json.Marshal(esd)
	if err != nil {
		return errors.Wrap(err, "could not marshal entity style descriptor")
	}
	s, err := GetWalletRenderingSchema(EntityStylesSchema)
	if err != nil {
		return errors.Wrap(err, "could not get entity styles schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "entity style not valid against schema")
	}
	return nil
}

// IsValidDisplayMappingObject validates a display mapping object against its known schema
func IsValidDisplayMappingObject(dmo DisplayMappingObject) error {
	jsonBytes, err := json.Marshal(dmo)
	if err != nil {
		return errors.Wrap(err, "could not marshal display mapping object")
	}
	s, err := GetWalletRenderingSchema(DisplayMappingObjectSchema)
	if err != nil {
		return errors.Wrap(err, "could not get display mapping object schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "display mapping object not valid against schema")
	}
	return nil
}

// IsValidLabeledDisplayMappingObject validates a labeled display mapping object against its known schema
func IsValidLabeledDisplayMappingObject(ldmo LabeledDisplayMappingObject) error {
	jsonBytes, err := json.Marshal(ldmo)
	if err != nil {
		return errors.Wrap(err, "could not marshal labeled display mapping object")
	}
	s, err := GetWalletRenderingSchema(LabeledDisplayMappingObjectSchema)
	if err != nil {
		return errors.Wrap(err, "could not get labeled display mapping object schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "labeled display mapping object not valid against schema")
	}
	return nil
}

func GetWalletRenderingSchema(schemaFile WalletRenderingSchema) (string, error) {
	b, err := knownSchemas.ReadFile("known_schemas/" + schemaFile.String())
	return string(b), err
}
