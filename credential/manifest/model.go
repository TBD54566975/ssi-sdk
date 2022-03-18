package manifest

import (
	"github.com/TBD54566975/did-sdk/credential/exchange"
	"github.com/TBD54566975/did-sdk/util"
)

// CredentialManifest https://identity.foundation/credential-manifest/#general-composition
type CredentialManifest struct {
	ID                     string                           `json:"id" validate:"required"`
	Issuer                 Issuer                           `json:"issuer" validate:"required,dive"`
	OutputDescriptors      []OutputDescriptor               `json:"output_descriptors" validate:"required,dive"`
	Format                 *exchange.ClaimFormat            `json:"format,omitempty" validate:"dive"`
	PresentationDefinition *exchange.PresentationDefinition `json:"presentation_definition,omitempty" validate:"dive"`
}

type Issuer struct {
	ID   string `json:"id" validate:"required"`
	Name string `json:"name,omitempty"`
	// an object or URI as defined by the DIF Entity Styles specification
	// https://identity.foundation/wallet-rendering/#entity-styles
	// TODO(gabe) https://github.com/TBD54566975/did-sdk/issues/52
	Styles interface{} `json:"styles,omitempty"`
}

// OutputDescriptor https://identity.foundation/credential-manifest/#output-descriptor
type OutputDescriptor struct {
	// Must be unique within a manifest
	ID          string `json:"id" validate:"required"`
	Schema      string `json:"schema" validate:"required"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// both below: an object or URI as defined by the DIF Entity Styles specification
	// https://identity.foundation/wallet-rendering/#entity-styles
	// TODO(gabe) https://github.com/TBD54566975/did-sdk/issues/52
	Styles  interface{} `json:"styles,omitempty"`
	Display interface{} `json:"display,omitempty"`
}

func (cm *CredentialManifest) IsValid() error {
	return util.NewValidator().Struct(cm)
}

// CredentialApplication https://identity.foundation/credential-manifest/#credential-application
type CredentialApplication struct {
	Application Application `json:"credential_application" validate:"required"`
	// Must be present if the corresponding manifest contains a presentation_definition
	PresentationSubmission *exchange.PresentationSubmission `json:"presentation_submission,omitempty" validate:"dive"`
}

type Application struct {
	ID         string                `json:"id" validate:"required"`
	ManifestID string                `json:"manifest_id" validate:"required"`
	Format     *exchange.ClaimFormat `json:"format" validate:"required,dive"`
}

// CredentialFulfillment https://identity.foundation/credential-manifest/#credential-fulfillment
type CredentialFulfillment struct {
	ID            string                          `json:"id" validate:"required"`
	ManifestID    string                          `json:"manifest_id" validate:"required"`
	DescriptorMap []exchange.SubmissionDescriptor `json:"descriptor_map" validate:"required"`
}

// TODO(gabe) support multiple embed targets https://github.com/TBD54566975/did-sdk/issues/57
