package credential

import (
	"github.com/TBD54566975/did-sdk/credential/exchange"
	"github.com/TBD54566975/did-sdk/credential/manifest"
	"github.com/TBD54566975/did-sdk/schema"
	"github.com/gobuffalo/packr/v2"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

const (
	credentialManifestSchema    string = "cm-credential-manifest.json"
	credentialApplicationSchema string = "cm-credential-application.json"
	credentialFulfillmentSchema string = "cm-credential-fulfillment.json"
	outputDescriptorsSchema     string = "cm-output-descriptors.json"

	presentationDefinitionSchema string = "pe-presentation-definition.json"
	formatDeclarationSchema      string = "pe-format-declaration.json"
	submissionRequirementsSchema string = "pe-submission-requirements.json"
)

var (
	schemaBox = packr.New("Presentation Exchange & Credential Manifest JSON Schemas", "./known_schemas")
)

func IsValidCredentialManifest(manifest manifest.CredentialManifest) error {
	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		return errors.Wrap(err, "could not marshal manifest to JSON")
	}
	s, err := getKnownSchema(credentialManifestSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential manifest schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func IsValidCredentialApplication(application manifest.CredentialApplication) error {
	jsonBytes, err := json.Marshal(application)
	if err != nil {
		return errors.Wrap(err, "could not marshal application to JSON")
	}
	s, err := getKnownSchema(credentialApplicationSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential application schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func IsValidCredentialFulfillment(fulfillment manifest.CredentialFulfillment) error {
	jsonBytes, err := json.Marshal(fulfillment)
	if err != nil {
		return errors.Wrap(err, "could not marshal fulfillment to JSON")
	}
	s, err := getKnownSchema(credentialFulfillmentSchema)
	if err != nil {
		return errors.Wrap(err, "could not get credential fulfillment schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func AreValidOutputDescriptors(descriptors []manifest.OutputDescriptor) error {
	jsonBytes, err := json.Marshal(descriptors)
	if err != nil {
		return errors.Wrap(err, "could not marshal output descriptors to JSON")
	}
	s, err := getKnownSchema(outputDescriptorsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get output descriptors schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func IsValidPresentationDefinition(manifest exchange.PresentationDefinition) error {
	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		return errors.Wrap(err, "could not marshal presentation definition to JSON")
	}
	s, err := getKnownSchema(presentationDefinitionSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation definition schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func IsValidFormatDeclaration(format exchange.ClaimFormat) error {
	jsonBytes, err := json.Marshal(format)
	if err != nil {
		return errors.Wrap(err, "could not marshal claim format to JSON")
	}
	s, err := getKnownSchema(formatDeclarationSchema)
	if err != nil {
		return errors.Wrap(err, "could not get claim format schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func AreValidSubmissionRequirements(requirements []exchange.SubmissionRequirement) error {
	jsonBytes, err := json.Marshal(requirements)
	if err != nil {
		return errors.Wrap(err, "could not marshal submission requirements to JSON")
	}
	s, err := getKnownSchema(submissionRequirementsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get submission requirements schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

func getKnownSchema(fileName string) (string, error) {
	return schemaBox.FindString(fileName)
}
