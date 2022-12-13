package exchange

import (
	"embed"
	"strings"

	"github.com/TBD54566975/ssi-sdk/schema"
	"github.com/goccy/go-json"
	"github.com/pkg/errors"
)

var (
	//go:embed known_schemas
	knownSchemas embed.FS
)

type PresentationExchangeSchema string

func (pe PresentationExchangeSchema) String() string {
	return string(pe)
}

const (
	PresentationDefinitionSchema              PresentationExchangeSchema = "pe-presentation-definition.json"
	PresentationDefinitionEnvelopeSchema      PresentationExchangeSchema = "pe-presentation-definition-envelope.json"
	PresentationSubmissionSchema              PresentationExchangeSchema = "pe-presentation-submission.json"
	PresentationClaimFormatDesignationsSchema PresentationExchangeSchema = "pe-definition-claim-format-designations.json"
	SubmissionClaimFormatDesignationsSchema   PresentationExchangeSchema = "pe-submission-claim-format-designations.json"
	SubmissionRequirementSchema               PresentationExchangeSchema = "pe-submission-requirement.json"
	SubmissionRequirementsSchema              PresentationExchangeSchema = "pe-submission-requirements.json"
)

func (PresentationExchangeSchema) LocalLoad() (map[string]string, error) {
	schemaDirectory := "known_schemas"
	local := map[string]string{
		"https://identity.foundation/presentation-exchange/schemas/presentation-definition.json":                           strings.Join([]string{schemaDirectory, PresentationDefinitionSchema.String()}, "/"),
		"https://identity.foundation/presentation-exchange/schemas/presentation-definition-envelope.json":                  strings.Join([]string{schemaDirectory, PresentationDefinitionEnvelopeSchema.String()}, "/"),
		"https://identity.foundation/presentation-exchange/schemas/presentation-submission.json":                           strings.Join([]string{schemaDirectory, PresentationSubmissionSchema.String()}, "/"),
		"https://identity.foundation/claim-format-registry/schemas/presentation-definition-claim-format-designations.json": strings.Join([]string{schemaDirectory, PresentationClaimFormatDesignationsSchema.String()}, "/"),
		"https://identity.foundation/claim-format-registry/schemas/presentation-submission-claim-format-designations.json": strings.Join([]string{schemaDirectory, SubmissionClaimFormatDesignationsSchema.String()}, "/"),
		"https://identity.foundation/presentation-exchange/schemas/submission-requirement.json":                            strings.Join([]string{schemaDirectory, SubmissionRequirementSchema.String()}, "/"),
		"https://identity.foundation/presentation-exchange/schemas/submission-requirements.json":                           strings.Join([]string{schemaDirectory, SubmissionRequirementsSchema.String()}, "/"),
	}
	for k, v := range local {
		schemaBytes, err := knownSchemas.ReadFile(v)
		if err != nil {
			return nil, err
		}
		local[k] = string(schemaBytes)
	}
	return local, nil
}

// IsValidPresentationDefinition validates a given presentation definition object against its known JSON schema
func IsValidPresentationDefinition(definition PresentationDefinition) error {
	jsonBytes, err := json.Marshal(definition)
	if err != nil {
		return errors.Wrap(err, "could not marshal presentation definition to JSON")
	}
	s, err := GetPresentationExchangeSchema(PresentationDefinitionSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation definition schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.New("presentation definition not valid against schema")
	}
	return nil
}

// IsValidPresentationDefinitionEnvelope validates a given presentation definition envelope object against its known JSON schema
func IsValidPresentationDefinitionEnvelope(definition PresentationDefinitionEnvelope) error {
	jsonBytes, err := json.Marshal(definition)
	if err != nil {
		return errors.Wrap(err, "could not marshal presentation definition to JSON")
	}
	s, err := GetPresentationExchangeSchema(PresentationDefinitionEnvelopeSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation definition schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
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
	s, err := GetPresentationExchangeSchema(PresentationSubmissionSchema)
	if err != nil {
		return errors.Wrap(err, "could not get presentation submission schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
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
	s, err := GetPresentationExchangeSchema(PresentationClaimFormatDesignationsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get claim format schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
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
	s, err := GetPresentationExchangeSchema(SubmissionRequirementSchema)
	if err != nil {
		return errors.Wrap(err, "could not get submission requirement schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
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
	s, err := GetPresentationExchangeSchema(SubmissionRequirementsSchema)
	if err != nil {
		return errors.Wrap(err, "could not get submission requirements schema")
	}
	if err = schema.IsJSONValidAgainstSchema(string(jsonBytes), s); err != nil {
		return errors.Wrap(err, "submission requirements not valid against schema")
	}
	return nil
}

func GetPresentationExchangeSchema(schemaFile PresentationExchangeSchema) (string, error) {
	b, err := knownSchemas.ReadFile("known_schemas/" + schemaFile.String())
	return string(b), err
}
