package exchange

import (
	"github.com/TBD54566975/did-sdk/schema"
	"github.com/gobuffalo/packr/v2"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

const (
	presentationDefinitionSchema string = "pe-presentation-definition.json"
	formatDeclarationSchema      string = "pe-format-declaration.json"
	submissionRequirementsSchema string = "pe-submission-requirements.json"
)

var (
	schemaBox = packr.New("Presentation Exchange JSON Schemas", "../known_schemas")
)

// IsValidPresentationDefinition validates a given presentation definition object against its known JSON schema
func IsValidPresentationDefinition(definition PresentationDefinition) error {
	definitionWrapper := struct {
		PresentationDefinition PresentationDefinition `json:"presentation_definition"`
	}{
		PresentationDefinition: definition,
	}
	jsonBytes, err := json.Marshal(definitionWrapper)
	if err != nil {
		return errors.Wrap(err, "could not marshal presentation definition to JSON")
	}
	s, err := getKnownSchema(presentationDefinitionSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation definition schema")
	}
	return schema.IsJSONValidAgainstSchema(string(jsonBytes), s)
}

// IsValidFormatDeclaration validates a given claim format object against its known JSON schema
func IsValidFormatDeclaration(format ClaimFormat) error {
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

// AreValidSubmissionRequirements validates a set of submission requirement objects against its known JSON schema
func AreValidSubmissionRequirements(requirements []SubmissionRequirement) error {
	requirementsWrapper := struct {
		SubmissionRequirements []SubmissionRequirement `json:"submission_requirements"`
	}{
		SubmissionRequirements: requirements,
	}
	jsonBytes, err := json.Marshal(requirementsWrapper)
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
