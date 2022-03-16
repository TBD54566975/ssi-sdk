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
	// an object or URI as defined by the DIF Entity Styles specification
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

// CredentialApplication https://identity.foundation/credential-manifest/#credential-application
type CredentialApplication struct {
	Application Application `json:"credential_application" validate:"required"`
	// Must be present if the corresponding manifest contains a presentation_definition
	// TODO(gabe) point to impl after https://github.com/TBD54566975/did-sdk/issues/18
	PresentationSubmission interface{} `json:"presentation_submission,omitempty"`
}

type Application struct {
	ID         string `json:"id" validate:"required"`
	ManifestID string `json:"manifest_id" validate:"required"`
	// TODO(gabe) unify format with the pres def impl in https://github.com/TBD54566975/did-sdk/issues/18
	Format interface{} `json:"format" validate:"required"`
}

// CredentialFulfillment https://identity.foundation/credential-manifest/#credential-fulfillment
type CredentialFulfillment struct {
	ID         string `json:"id" validate:"required"`
	ManifestID string `json:"manifest_id" validate:"required"`
	// TODO(gabe) unify with https://identity.foundation/presentation-exchange/#presentation-submission
	DescriptorMap interface{} `json:"descriptor_map" validate:"required"`
}

// TODO(gabe) support multiple embed targets https://identity.foundation/credential-manifest/#embed-targets-2
