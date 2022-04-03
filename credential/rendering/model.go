package rendering

import (
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/pkg/errors"
	"reflect"
)

// EntityStyleDescriptor https://identity.foundation/wallet-rendering/#entity-styles
type EntityStyleDescriptor struct {
	Thumbnail  *ImageResource `json:"thumbnail,omitempty"`
	Hero       *ImageResource `json:"hero,omitempty"`
	Background *ColorResource `json:"background,omitempty"`
	Text       *ColorResource `json:"text,omitempty"`
}

func (esd *EntityStyleDescriptor) IsEmpty() bool {
	if esd == nil {
		return true
	}
	return reflect.DeepEqual(esd, &EntityStyleDescriptor{})
}

type ImageResource struct {
	// Must be a valid URI string to an image resource
	URI string `json:"uri" validate:"required"`
	// Describes the alternate text for a logo image
	Alt string `json:"alt,omitempty"`
}

type ColorResource struct {
	// a HEX string color value (e.g. #00000)
	Color string `json:"color,omitempty"`
}

// DataDisplay https://identity.foundation/wallet-rendering/#data-display
type DataDisplay struct {
	Title       *DisplayMappingObject        `json:"title,omitempty"`
	Subtitle    *DisplayMappingObject        `json:"subtitle,omitempty"`
	Description *DisplayMappingObject        `json:"description,omitempty"`
	Properties  *LabeledDisplayMappingObject `json:"properties,omitempty"`
}

// DisplayMappingObject https://identity.foundation/wallet-rendering/#display-mapping-object
type DisplayMappingObject struct {
	// Either a path or text must be present

	// Ifa path is present it must be an array of JSON Path string expressions
	// and the schema property must also be present.
	Path     []string              `json:"path,omitempty"`
	Schema   *DisplayMappingSchema `json:"schema,omitempty"`
	Fallback string                `json:"fallback,omitempty"`

	// If path is not present, the text value is required with no other properties
	Text *string `json:"text,omitempty"`
}

func (dmo *DisplayMappingObject) IsEmpty() bool {
	if dmo == nil {
		return true
	}
	return reflect.DeepEqual(dmo, &DisplayMappingObject{})
}

func (dmo *DisplayMappingObject) IsValid() error {
	if dmo.IsEmpty() {
		return errors.New("display mapping object is empty")
	}
	if len(dmo.Path) > 0 {
		if dmo.Text != nil {
			return errors.New("path and text properties cannot be present at the same time")
		}
		if dmo.Schema == nil {
			return errors.New("schema cannot be empty when path is present")
		}
	} else if dmo.Text == nil || len(*dmo.Text) == 0 {
		return errors.New("display mapping object must have path or text present")
	}
	return util.NewValidator().Struct(dmo)
}

type (
	SchemaType   string
	SchemaFormat string
)

const (
	// the following are defined in the spec https://identity.foundation/wallet-rendering/#using-path

	StringType  SchemaType = "string"
	BooleanType SchemaType = "boolean"
	NumberType  SchemaType = "number"
	IntegerType SchemaType = "integer"

	DateTimeFormat     SchemaFormat = "date-time"
	TimeFormat         SchemaFormat = "time"
	DateFormat         SchemaFormat = "date"
	EmailFormat        SchemaFormat = "email"
	IDNEmailFormat     SchemaFormat = "idn-email"
	HostnameFormat     SchemaFormat = "hostname"
	IDNHostnameFormat  SchemaFormat = "idn-hostname"
	IPV4Format         SchemaFormat = "ipv4"
	IPV6Format         SchemaFormat = "ipv6"
	URIFormat          SchemaFormat = "uri"
	URIReferenceFormat SchemaFormat = "uri-reference"
	IRIFormat          SchemaFormat = "iri"
	IRIReferenceFormat SchemaFormat = "iri-reference"
)

type DisplayMappingSchema struct {
	Type SchemaType `json:"type" validate:"required"`
	// Must be present if the value of the type property is "string"
	Format SchemaFormat `json:"format,omitempty"`
}

// LabeledDisplayMappingObject https://identity.foundation/wallet-rendering/#labeled-display-mapping-object
type LabeledDisplayMappingObject struct {
	Label                 string `json:"label" validate:"required"`
	*DisplayMappingObject `validate:"dive"`
}

func (ldmo *LabeledDisplayMappingObject) IsEmpty() bool {
	if ldmo == nil {
		return true
	}
	return reflect.DeepEqual(ldmo, &LabeledDisplayMappingObject{})
}

func (ldmo *LabeledDisplayMappingObject) IsValid() error {
	if ldmo.IsEmpty() {
		return errors.New("labeled display mapping object is empty")
	}
	if ldmo.DisplayMappingObject == nil {
		return errors.New("embedded display mapping object cannot be nil")
	}
	return util.NewValidator().Struct(ldmo)
}
