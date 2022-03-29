package exchange

import (
	"fmt"
	"github.com/TBD54566975/did-sdk/credential"
	"github.com/TBD54566975/did-sdk/credential/signing"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/TBD54566975/did-sdk/util"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
	"strings"
)

// VerifyPresentationSubmission verifies a presentation submission for both signature validity and correctness
// with the specification. It is assumed that the caller knows the submission embed target, and the corresponding
// presentation definition, and has access to the public key of the signer.
func VerifyPresentationSubmission(verifier cryptosuite.Verifier, et EmbedTarget, def PresentationDefinition, submission []byte) error {
	if err := canProcessDefinition(def); err != nil {
		return errors.Wrap(err, "feature not supported in processing given presentation definition")
	}
	if !IsSupportedEmbedTarget(et) {
		return fmt.Errorf("unsupported presentation submission embed target type: %s", et)
	}
	switch et {
	case JWTVPTarget:
		jwkVerifier, ok := verifier.(*cryptosuite.JSONWebKeyVerifier)
		if !ok {
			return fmt.Errorf("verifier not valid for request type: %s", et)
		}
		vp, err := signing.VerifyVerifiablePresentationJWT(*jwkVerifier, string(submission))
		if err != nil {
			return errors.Wrap(err, "verification of the presentation submission failed")
		}
		return VerifyPresentationSubmissionVP(def, *vp)
	default:
		return fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
	}
}

// VerifyPresentationSubmissionVP verifies whether a verifiable presentation is a valid presentation submission
// for a given presentation definition.
// TODO(gabe) handle signature validation of submission claims https://github.com/TBD54566975/did-sdk/issues/71
func VerifyPresentationSubmissionVP(def PresentationDefinition, vp credential.VerifiablePresentation) error {
	if err := vp.IsValid(); err != nil {
		return errors.Wrap(err, "presentation submission does not contain a valid VP")
	}

	// first, validate the presentation submission in the VP
	submission, ok := vp.PresentationSubmission.(PresentationSubmission)
	if !ok {
		return errors.New("unable to parse presentation submission from verifiable presentation")
	}
	if err := submission.IsValid(); err != nil {
		return errors.Wrap(err, "invalid presentation submission in provided verifiable presentation")
	}
	if submission.DefinitionID != def.ID {
		return fmt.Errorf("mismatched between presentation definition ID<%s> and submission's definition ID<%s>",
			def.ID, submission.DefinitionID)
	}

	// index submission descriptors by id of the input descriptor
	submissionDescriptorLookup := make(map[string]SubmissionDescriptor)
	for _, d := range submission.DescriptorMap {
		submissionDescriptorLookup[d.ID] = d
	}

	// turn the vp into JSON so we can use the paths from the submission descriptor to resolve each claim
	vpJSON, err := util.ToJSONMap(vp)
	if err != nil {
		return errors.Wrap(err, "could not turn VP into JSON representation")
	}

	// validate each input descriptor is fulfilled
	for _, inputDescriptor := range def.InputDescriptors {
		submissionDescriptor, ok := submissionDescriptorLookup[inputDescriptor.ID]
		if !ok {
			return fmt.Errorf("unfulfilled input descriptor<%s>; submission not valid", inputDescriptor.ID)
		}

		// if the format on the submitted claim does not match the input descriptor, we cannot process
		if !util.Contains(submissionDescriptor.Format, inputDescriptor.Format.FormatValues()) {
			return fmt.Errorf("for input descriptor<%s>, the format of submission descriptor<%s> is not one"+
				"  of the supported formats: %s", inputDescriptor.ID, submissionDescriptor.Format,
				strings.Join(inputDescriptor.Format.FormatValues(), ", "))
		}

		// TODO(gabe) support nested paths in presentation submissions
		// https://github.com/TBD54566975/did-sdk/issues/73
		if submissionDescriptor.PathNested != nil {
			return fmt.Errorf("submission with nested paths not supported: %s", submissionDescriptor.ID)
		}

		// make sure the format is as expected
		if !util.Contains(submissionDescriptor.Format, inputDescriptor.Format.FormatValues()) {
			return fmt.Errorf("unsupported format<%s> for input descriptor which supports: %s",
				submissionDescriptor.Format, strings.Join(inputDescriptor.Format.FormatValues(), ", "))
		}

		// resolve the claim from the JSON path expression in the submission descriptor
		submittedClaim, err := jsonpath.JsonPathLookup(vpJSON, submissionDescriptor.Path)
		if err != nil {
			return errors.Wrapf(err, "could not resolve claim from submission descriptor<%s> with path: %s",
				submissionDescriptor.ID, submissionDescriptor.Path)
		}

		// verify the submitted claim complies with the input descriptor

		// if there are no constraints, we are done checking for validity
		if inputDescriptor.Constraints == nil {
			continue
		}

		// TODO(gabe) consider enforcing limited disclosure if present
		// for each field we need to verify at least one path matches
		for _, field := range inputDescriptor.Constraints.Fields {
			if err := findMatchingPath(submittedClaim, field.Path); err != nil {
				return errors.Wrapf(err, "input descriptor<%s> not fulfilled for field: %s", inputDescriptor.ID, field.ID)
			}
		}
	}
	return nil
}

func findMatchingPath(claim interface{}, paths []string) error {
	for _, path := range paths {
		if _, err := jsonpath.JsonPathLookup(claim, path); err == nil {
			return nil
		}
	}
	return errors.New("matching path for claim could not be found")
}
