package manifest

import "github.com/TBD54566975/did-sdk/util"

// CredentialManifest https://identity.foundation/credential-manifest/#general-composition
type CredentialManifest struct {
	Issuer            Issuer             `json:"issuer" validate:"required,dive"`
	OutputDescriptors []OutputDescriptor `json:"output_descriptors" validate:"required"`
	// TODO(gabe) unify these properties with the pres def impl in https://github.com/TBD54566975/did-sdk/issues/18
	Format                 interface{} `json:"format,omitempty"`
	PresentationDefinition interface{} `json:"presentation_definition,omitempty"`
}

type Issuer struct {
	ID   string `json:"id" validate:"required"`
	Name string `json:"name,omitempty"`
	// an object or URI as defined by the  DIFEntity Styles specification
	// https://identity.foundation/wallet-rendering/#entity-styles
	Styles interface{} `json:"styles,omitempty"`
}

// OutputDescriptor https://identity.foundation/credential-manifest/#output-descriptor
type OutputDescriptor struct {
	// Must be unique within a manifest
	ID          string `json:"id" validate:"required"`
	Schema      string `json:"schema" validate:"required"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// an object or URI as defined by the DIF Entity Styles specification
	// https://identity.foundation/wallet-rendering/#entity-styles
	Styles interface{} `json:"styles,omitempty"`
	// an object as defined by the DIF Data Display spec
	// https://identity.foundation/wallet-rendering/#data-display
	Display interface{} `json:"display,omitempty"`
}

func (cm *CredentialManifest) IsValid() error {
	return util.NewValidator().Struct(cm)
}
