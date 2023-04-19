package exchange

import (
	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

// IsValidPresentationDefinition validates a given presentation definition object against its known JSON schema
func IsValidPresentationDefinition(definition PresentationDefinition) error {
	jsonBytes, err := json.Marshal(definition)
	if err != nil {
		return errors.Wrap(err, "could not marshal presentation definition to JSON")
	}
	s, err := schema.LoadSchema(schema.PresentationDefinitionSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation definition schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "presentation definition not valid against schema")
	}
	return nil
}

// IsValidPresentationDefinitionEnvelope validates a given presentation definition envelope object against its known JSON schema
func IsValidPresentationDefinitionEnvelope(definition PresentationDefinitionEnvelope) error {
	jsonBytes, err := json.Marshal(definition)
	if err != nil {
		return errors.Wrap(err, "could not marshal presentation definition to JSON")
	}
	s, err := schema.LoadSchema(schema.PresentationDefinitionEnvelopeSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation definition schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "presentation definition not valid against schema")
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
	s, err := schema.LoadSchema(schema.PresentationSubmissionSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation submission schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "submission declaration not valid against schema")
	}
	return nil
}

// IsValidDefinitionClaimFormatDesignation validates a given claim format object against its known JSON schema
func IsValidDefinitionClaimFormatDesignation(format ClaimFormat) error {
	jsonBytes, err := json.Marshal(format)
	if err != nil {
		return errors.Wrap(err, "could not marshal claim format to JSON")
	}
	s, err := schema.LoadSchema(schema.PresentationClaimFormatDesignationsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get claim format schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "format declaration not valid against schema")
	}
	return nil
}

// IsValidSubmissionRequirement validates a submission requirement object against its known JSON schema
func IsValidSubmissionRequirement(requirement SubmissionRequirement) error {
	jsonBytes, err := json.Marshal(requirement)
	if err != nil {
		return errors.Wrap(err, "could not marshal submission requirement to JSON")
	}
	s, err := schema.LoadSchema(schema.SubmissionRequirementSchema)
	if err != nil {
		return errors.Wrap(err, "could not get submission requirement schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "submission requirement not valid against schema")
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
	s, err := schema.LoadSchema(schema.SubmissionRequirementsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get submission requirements schema")
	}
	if err = schema.IsValidAgainstJSONSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "submission requirements not valid against schema")
	}
	return nil
}
