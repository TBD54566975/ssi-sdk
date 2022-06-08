package exchange

import (
	"github.com/gobuffalo/packr/v2"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/ssi-sdk/schema"
)

const (
	presentationDefinitionSchema         string = "pe-presentation-definition.json"
	presentationDefinitionEnvelopeSchema string = "pe-presentation-definition-envelope.json"
	presentationSubmissionSchema         string = "pe-presentation-submission.json"
	formatDeclarationSchema              string = "pe-format-declaration.json"
	submissionRequirementSchema          string = "pe-submission-requirement.json"
	submissionRequirementsSchema         string = "pe-submission-requirements.json"
)

var (
	schemaBox = packr.New("Presentation Exchange JSON Schemas", "../known_schemas")
)

// IsValidPresentationDefinition validates a given presentation definition object against its known JSON schema
func IsValidPresentationDefinition(definition PresentationDefinition) error {
	jsonBytes, err := json.Marshal(definition)
	if err != nil {
		return errors.Wrap(err, "could not marshal presentation definition to JSON")
	}
	s, err := getKnownSchema(presentationDefinitionSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation definition schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("presentation definition not valid against schema")
		return err
	}
	return nil
}

// IsValidPresentationDefinitionEnvelope validates a given presentation definition envelope object against its known JSON schema
func IsValidPresentationDefinitionEnvelope(definition PresentationDefinitionEnvelope) error {
	jsonBytes, err := json.Marshal(definition)
	if err != nil {
		return errors.Wrap(err, "could not marshal presentation definition to JSON")
	}
	s, err := getKnownSchema(presentationDefinitionEnvelopeSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation definition schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("presentation definition not valid against schema")
		return err
	}
	return nil
}

// IsValidPresentationSubmission validates a given presentation submission object against its known JSON schema
func IsValidPresentationSubmission(submission PresentationSubmission) error {
	submissionWrapper := struct {
		PresentationSubmission PresentationSubmission `json:"presentation_submission"`
	}{
		PresentationSubmission: submission,
	}
	jsonBytes, err := json.Marshal(submissionWrapper)
	if err != nil {
		return errors.Wrap(err, "could not marshal presentation submission to JSON")
	}
	s, err := getKnownSchema(presentationSubmissionSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation submission schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("submission declaration not valid against schema")
		return err
	}
	return nil
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
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("format declaration not valid against schema")
		return err
	}
	return nil
}

// IsValidSubmissionRequirement validates a submission requirement object against its known JSON schema
func IsValidSubmissionRequirement(requirement SubmissionRequirement) error {
	jsonBytes, err := json.Marshal(requirement)
	if err != nil {
		return errors.Wrap(err, "could not marshal submission requirement to JSON")
	}
	s, err := getKnownSchema(submissionRequirementSchema)
	if err != nil {
		return errors.Wrap(err, "could not get submission requirement schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("submission requirement not valid against schema")
		return err
	}
	return nil
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
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		logrus.WithError(err).Error("submission requirements not valid against schema")
		return err
	}
	return nil
}

func getKnownSchema(fileName string) (string, error) {
	return schemaBox.FindString(fileName)
}
