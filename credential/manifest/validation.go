package manifest

import (
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	credutil "github.com/TBD54566975/ssi-sdk/credential/util"
	errresp "github.com/TBD54566975/ssi-sdk/error"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
)

// IsValidCredentialApplicationForManifest validates the rules on how a credential manifest [cm] and credential
// application [ca] relate to each other https://identity.foundation/credential-manifest/#credential-application
// applicationAndCredsJSON is the credential application and credentials as a JSON object
func IsValidCredentialApplicationForManifest(cm CredentialManifest, applicationAndCredsJSON map[string]any) (map[string]string, error) {
	var err error

	// parse out the application to its known object model
	applicationJSON, ok := applicationAndCredsJSON[CredentialApplicationJSONProperty]
	if !ok {
		err = errresp.NewErrorResponse(errresp.ApplicationError, "credential_application property not found")
		return nil, err
	}

	applicationBytes, err := json.Marshal(applicationJSON)
	if err != nil {
		err = errresp.NewErrorResponseWithErrorAndMsg(errresp.CriticalError, err, "failed to marshal credential application")
		return nil, err
	}
	var ca CredentialApplication
	if err = json.Unmarshal(applicationBytes, &ca); err != nil {
		err = errresp.NewErrorResponseWithErrorAndMsg(errresp.CriticalError, err, "failed to unmarshal credential application")
		return nil, err
	}

	// Basic Validation Checks
	if err = cm.IsValid(); err != nil {
		err = errresp.NewErrorResponseWithErrorAndMsg(errresp.ApplicationError, err, "credential manifest is not valid")
		return nil, err
	}

	if err = ca.IsValid(); err != nil {
		err = errresp.NewErrorResponseWithErrorAndMsg(errresp.ApplicationError, err, "credential application is not valid")
		return nil, err
	}

	// The object MUST contain a manifest_id property. The value of this property MUST be the id of a valid Credential Manifest.
	if cm.ID != ca.ManifestID {
		err = errresp.NewErrorResponsef(errresp.ApplicationError, "the credential application's manifest id: "+
			"%s must be equal to the credential manifest's id: %s", ca.ManifestID, cm.ID)
		return nil, err
	}

	// The ca must have a format property if the related Credential Manifest specifies a format property.
	// Its value must be a subset of the format property in the Credential Manifest that this Credential Submission
	if !cm.Format.IsEmpty() {
		cmFormats := make(map[string]bool)

		for _, format := range cm.Format.FormatValues() {
			cmFormats[format] = true
		}

		for _, format := range ca.Format.FormatValues() {
			if _, ok = cmFormats[format]; !ok {
				err = errresp.NewErrorResponse(errresp.ApplicationError, "credential application's "+
					"format must be a subset of the format property in the credential manifest")
				return nil, err
			}
		}
	}

	if (cm.PresentationDefinition != nil && len(cm.PresentationDefinition.InputDescriptors) > 0) &&
		(ca.PresentationSubmission == nil || len(ca.PresentationSubmission.DescriptorMap) == 0) {
		err = errresp.NewErrorResponsef(errresp.ApplicationError, "no descriptors provided for application: "+
			"%s against manifest: %s", ca.ID, cm.ID)
		return nil, err
	}

	// The Credential Application object MUST contain a presentation_submission property IF the related Credential
	// Manifest contains a presentation_definition. Its value MUST be a valid Presentation Submission:
	if cm.PresentationDefinition.IsEmpty() {
		if ca.PresentationSubmission != nil {
			err = errresp.NewErrorResponse(errresp.ApplicationError, "credential application's "+
				"presentation submission is invalid; the credential manifest's presentation definition is empty")
		}
		return nil, err
	}

	if ca.PresentationSubmission.IsEmpty() {
		err = errresp.NewErrorResponse(errresp.ApplicationError, "credential application's "+
			"presentation submission cannot be empty because the credential manifest's presentation definition is not empty")
		return nil, err
	}

	if err = cm.PresentationDefinition.IsValid(); err != nil {
		err = errresp.NewErrorResponseWithErrorAndMsg(errresp.ApplicationError, err, "credential manifest's"+
			" presentation definition is not valid")
		return nil, err
	}

	if err = ca.PresentationSubmission.IsValid(); err != nil {
		err = errresp.NewErrorResponseWithErrorAndMsg(errresp.ApplicationError, err, "credential "+
			"application's presentation submission is not valid")
		return nil, err
	}

	// https://identity.foundation/presentation-exchange/#presentation-submission
	// The presentation_submission object MUST contain a definition_id property. The value of this property MUST be the id value of a valid Presentation Definition.
	if cm.PresentationDefinition.ID != ca.PresentationSubmission.DefinitionID {
		err = errresp.NewErrorResponsef(errresp.ApplicationError, "credential application's presentation "+
			"submission's definition id: %s does not match the credential manifest's id: %s", ca.PresentationSubmission.DefinitionID, cm.PresentationDefinition.ID)
		return nil, err
	}

	// The descriptor_map object MUST include a format property. The value of this property MUST be a string that matches one of the Claim Format Designation. This denotes the data format of the Claim.
	claimFormats := make(map[string]bool)
	for _, format := range exchange.SupportedClaimFormats() {
		claimFormats[string(format)] = true
	}

	for _, submissionDescriptor := range ca.PresentationSubmission.DescriptorMap {
		if _, ok = claimFormats[submissionDescriptor.Format]; !ok {
			err = errresp.NewErrorResponse(errresp.ApplicationError, "claim format is invalid or not supported")
			return nil, err
		}

		// The descriptor_map object MUST include a path property. The value of this property MUST be a JSONPath string expression.
		if _, err = jsonpath.Compile(submissionDescriptor.Path); err != nil {
			err = errresp.NewErrorResponsef(errresp.ApplicationError, "invalid json path: %s", submissionDescriptor.Path)
			return nil, err
		}
	}

	// index submission descriptors by id of the input descriptor
	submissionDescriptorLookup := make(map[string]exchange.SubmissionDescriptor)
	for _, d := range ca.PresentationSubmission.DescriptorMap {
		submissionDescriptorLookup[d.ID] = d
	}

	// validate each input descriptor is fulfilled
	unfulfilledInputDescriptors := make(map[string]string)
	for _, inputDescriptor := range cm.PresentationDefinition.InputDescriptors {
		submissionDescriptor, ok := submissionDescriptorLookup[inputDescriptor.ID]
		if !ok {
			unfulfilledInputDescriptors[inputDescriptor.ID] = "no submission descriptor found for input descriptor"
			continue
		}

		// if the format on the submitted claim does not match the input descriptor, we cannot process
		if inputDescriptor.Format != nil && !util.Contains(submissionDescriptor.Format, inputDescriptor.Format.FormatValues()) {
			errMsg := fmt.Sprintf("the format of submission descriptor<%s> is not one"+
				" of the supported formats: %s", submissionDescriptor.Format,
				strings.Join(inputDescriptor.Format.FormatValues(), ", "))
			unfulfilledInputDescriptors[inputDescriptor.ID] = errMsg
			continue
		}

		// TODO(gabe) support nested paths in presentation submissions
		// https://github.com/TBD54566975/ssi-sdk/issues/73
		if submissionDescriptor.PathNested != nil {
			errMsg := fmt.Sprintf("submission with nested paths not supported: %s", submissionDescriptor.ID)
			unfulfilledInputDescriptors[inputDescriptor.ID] = errMsg
			continue
		}

		// resolve the claim from the JSON path expression in the submission descriptor
		submittedClaim, pathErr := jsonpath.JsonPathLookup(applicationAndCredsJSON, submissionDescriptor.Path)
		if pathErr != nil {
			errMsg := fmt.Sprintf("could not resolve claim from submission descriptor<%s> with path: %s",
				submissionDescriptor.ID, submissionDescriptor.Path)
			unfulfilledInputDescriptors[inputDescriptor.ID] = errMsg
			continue
		}

		// convert submitted claim vc to map[string]any
		cred, credErr := credutil.ToCredential(submittedClaim)
		if credErr != nil {
			unfulfilledInputDescriptors[inputDescriptor.ID] = "failed to extract credential from json"
			continue
		}
		if err = cred.IsValid(); err != nil {
			unfulfilledInputDescriptors[inputDescriptor.ID] = "credential is not valid"
			continue
		}

		// verify the submitted claim complies with the input descriptor

		// if there are no constraints, we are done checking for validity
		if inputDescriptor.Constraints == nil {
			continue
		}

		// TODO(gabe) consider enforcing limited disclosure if present
		// for each field we need to verify at least one path matches
		credJSON, err := credutil.ToCredentialJSONMap(submittedClaim)
		if err != nil {
			unfulfilledInputDescriptors[inputDescriptor.ID] = "failed to extract credential from json"
			continue
		}
		for _, field := range inputDescriptor.Constraints.Fields {
			if err = findMatchingPath(credJSON, field.Path); err != nil {
				errMsg := fmt.Sprintf("input descriptor not fulfilled for field: %s", field.ID)
				unfulfilledInputDescriptors[inputDescriptor.ID] = errMsg
				continue
			}
		}
	}
	numUnfulfilledInputDescriptors := len(unfulfilledInputDescriptors)
	if numUnfulfilledInputDescriptors > 0 {
		err = errresp.NewErrorResponsef(errresp.ApplicationError, "credential application not valid; "+
			"<%d>unfulfilled input descriptor(s)", numUnfulfilledInputDescriptors)
		return unfulfilledInputDescriptors, err
	}

	return unfulfilledInputDescriptors, err
}

func findMatchingPath(claim any, paths []string) error {
	for _, path := range paths {
		if _, err := jsonpath.JsonPathLookup(claim, path); err == nil {
			return nil
		}
	}
	return errors.New("matching path for claim could not be found")
}

// TODO(gabe) support multiple embed targets https://github.com/TBD54566975/ssi-sdk/issues/57
