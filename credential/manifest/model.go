package manifest

import (
	"reflect"

	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/credential/rendering"
	"github.com/TBD54566975/ssi-sdk/util"
)

// CredentialManifest https://identity.foundation/credential-manifest/#general-composition
type CredentialManifest struct {
	ID                     string                           `json:"id" validate:"required"`
	SpecVersion            string                           `json:"spec_version" validate:"required"`
	Issuer                 Issuer                           `json:"issuer" validate:"required,dive"`
	OutputDescriptors      []OutputDescriptor               `json:"output_descriptors" validate:"required,dive"`
	Format                 *exchange.ClaimFormat            `json:"format,omitempty" validate:"omitempty,dive"`
	PresentationDefinition *exchange.PresentationDefinition `json:"presentation_definition,omitempty" validate:"omitempty,dive"`
}

func (cm *CredentialManifest) IsEmpty() bool {
	if cm == nil {
		return true
	}
	return reflect.DeepEqual(cm, &CredentialManifest{})
}

func (cm *CredentialManifest) IsValid() error {
	if cm.IsEmpty() {
		return errors.New("manifest is empty")
	}

	// validate against json schema
	if err := IsValidCredentialManifest(*cm); err != nil {
		return errors.Wrap(err, "manifest failed json schema validation")
	}

	// validate against json schema
	if err := AreValidOutputDescriptors(cm.OutputDescriptors); err != nil {
		return errors.Wrap(err, "manifest's output descriptors failed json schema validation")
	}

	// validate against struct tags
	return util.NewValidator().Struct(cm)
}

type Issuer struct {
	ID   string `json:"id" validate:"required"`
	Name string `json:"name,omitempty"`
	// an object or URI as defined by the DIF Entity Styles specification
	// https://identity.foundation/wallet-rendering/#entity-styles
	Styles *rendering.EntityStyleDescriptor `json:"styles,omitempty"`
}

// OutputDescriptor https://identity.foundation/credential-manifest/#output-descriptor
type OutputDescriptor struct {
	// Must be unique within a manifest
	ID          string `json:"id" validate:"required"`
	Schema      string `json:"schema" validate:"required"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// both below: an object or URI as defined by the DIF Entity Styles specification
	Display *rendering.DataDisplay           `json:"display,omitempty"`
	Styles  *rendering.EntityStyleDescriptor `json:"styles,omitempty"`
}

func (od *OutputDescriptor) IsEmpty() bool {
	if od == nil {
		return true
	}
	return reflect.DeepEqual(od, &OutputDescriptor{})
}

func (od *OutputDescriptor) IsValid() error {
	return util.NewValidator().Struct(od)
}

// CredentialApplication https://identity.foundation/credential-manifest/#credential-application
type CredentialApplication struct {
	ID          string                `json:"id" validate:"required"`
	SpecVersion string                `json:"spec_version" validate:"required"`
	ManifestID  string                `json:"manifest_id" validate:"required"`
	Format      *exchange.ClaimFormat `json:"format" validate:"required,dive"`
	// Must be present if the corresponding manifest contains a presentation_definition
	PresentationSubmission *exchange.PresentationSubmission `json:"presentation_submission,omitempty" validate:"omitempty,dive"`
}

func (ca *CredentialApplication) IsEmpty() bool {
	if ca == nil {
		return true
	}
	return reflect.DeepEqual(ca, &CredentialApplication{})
}

func (ca *CredentialApplication) IsValid() error {
	if ca.IsEmpty() {
		return errors.New("application is empty")
	}
	if err := IsValidCredentialApplication(*ca); err != nil {
		return errors.Wrap(err, "application failed json schema validation")
	}
	if ca.Format != nil {
		if err := exchange.IsValidDefinitionClaimFormatDesignation(*ca.Format); err != nil {
			return errors.Wrap(err, "application's claim format failed json schema validation")
		}
	}
	return util.NewValidator().Struct(ca)
}

// CredentialResponse https://identity.foundation/credential-manifest/#credential-response
type CredentialResponse struct {
	ID            string `json:"id" validate:"required"`
	SpecVersion   string `json:"spec_version" validate:"required"`
	ManifestID    string `json:"manifest_id" validate:"required"`
	ApplicationID string `json:"application_id"`
	Fulfillment   *struct {
		DescriptorMap []exchange.SubmissionDescriptor `json:"descriptor_map" validate:"required"`
	} `json:"fulfillment,omitempty" validate:"omitempty,dive"`
	Denial *struct {
		Reason           string   `json:"reason" validate:"required"`
		InputDescriptors []string `json:"input_descriptors"`
	} `json:"denial,omitempty" validate:"omitempty,dive"`
}

func (cf *CredentialResponse) IsEmpty() bool {
	if cf == nil {
		return true
	}
	return reflect.DeepEqual(cf, &CredentialResponse{})
}

func (cf *CredentialResponse) IsValid() error {
	if cf.IsEmpty() {
		return errors.New("response is empty")
	}
	if err := IsValidCredentialResponse(*cf); err != nil {
		return errors.Wrap(err, "response failed json schema validation")
	}
	return util.NewValidator().Struct(cf)
}

// IsValidPair validates the rules on how a credential manifest [cm] and credential application [ca] relate to each other https://identity.foundation/credential-manifest/#credential-application
func IsValidPair(cm CredentialManifest, ca CredentialApplication) error {

	err := cm.IsValid()
	if err != nil {
		return errors.Wrap(err, "credential manifest is not valid")
	}

	err = ca.IsValid()
	if err != nil {
		return errors.Wrap(err, "credential application is not valid")
	}

	// The object MUST contain a manifest_id property. The value of this property MUST be the id of a valid Credential Manifest.
	if cm.ID != ca.ManifestID {
		return errors.New("the credential application's manifest id must be equal to the credential manifest's id")
	}

	// The ca must have a format property if the related Credential Manifest specifies a format property.
	// Its value must be a subset of the format property in the Credential Manifest that this Credential Submission
	if !cm.Format.IsEmpty() {
		cmFormats := map[string]bool{}
		for _, format := range cm.Format.FormatValues() {
			cmFormats[format] = true
		}

		for _, format := range ca.Format.FormatValues() {
			if cmFormats[format] == false {
				return errors.New("credential application's format must be a subset of the format property in the credential manifest")
			}
		}
	}

	// The Credential Application object MUST contain a presentation_submission property IF the related Credential Manifest contains a presentation_definition.
	// Its value MUST be a valid Presentation Submission:
	if !cm.PresentationDefinition.IsEmpty() {

		if ca.PresentationSubmission.IsEmpty() {
			return errors.New("credential application's presentation submission cannot be empty")
		}

		err := cm.PresentationDefinition.IsValid()
		if err != nil {
			return errors.Wrap(err, "credential manifest's presentation definition is not valid")
		}

		err = ca.PresentationSubmission.IsValid()
		if err != nil {
			return errors.Wrap(err, "credential application's presentation submission is not valid")
		}

		// https://identity.foundation/presentation-exchange/#presentation-submission
		// The presentation_submission object MUST contain a definition_id property. The value of this property MUST be the id value of a valid Presentation Definition.
		if cm.PresentationDefinition.ID != ca.PresentationSubmission.DefinitionID {
			return errors.New("credential application's presentation submission's definition id does not match the credential manifest's id")
		}

		// The descriptor_map object MUST include a format property. The value of this property MUST be a string that matches one of the Claim Format Designation. This denotes the data format of the Claim.
		supportedClaimFormats := exchange.SupportedClaimFormats()
		for _, submissionDescriptor := range ca.PresentationSubmission.DescriptorMap {
			if supportedClaimFormats[submissionDescriptor.Format] != true {
				return errors.New("claim format is invalid or not supported")
			}
		}

		// TODO: Path validation
		// ?? The descriptor_map object MUST include a path property. The value of this property MUST be a JSONPath string expression.
		// The path property indicates the Claim submitted in relation to the identified Input Descriptor, when executed against the top-level of the object the Presentation Submission is embedded within.
		// cm.PresentationDefinition.InputDescriptors[0].
		// ca.PresentationSubmission.DescriptorMap[0].Path

	}

	return nil
}

// TODO(gabe) support multiple embed targets https://github.com/TBD54566975/ssi-sdk/issues/57
