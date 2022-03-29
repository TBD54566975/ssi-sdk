package exchange

import (
	"fmt"
	"github.com/TBD54566975/did-sdk/credential"
	"github.com/TBD54566975/did-sdk/credential/signing"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/TBD54566975/did-sdk/util"
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
		return fmt.Errorf("mismatched between presentation definition ID<%s> and submission's definition ID<%s>", def.ID, submission.DefinitionID)
	}

	// index submission descriptors by id of the input descriptor
	submissionDescriptorLookup := make(map[string]SubmissionDescriptor)
	for _, d := range submission.DescriptorMap {
		submissionDescriptorLookup[d.ID] = d
	}

	// turn the vp into JSON so we can use the paths from the submission descriptor

	//credentials := vp.VerifiableCredential
	// validate each input descriptor is fulfilled
	for _, inputDescriptor := range def.InputDescriptors {
		submissionDescriptor, ok := submissionDescriptorLookup[inputDescriptor.ID]
		if !ok {
			return fmt.Errorf("unfulfilled input descriptor<%s>; submission not valid", inputDescriptor.ID)
		}

		// make sure the format is as expected
		if !util.Contains(submissionDescriptor.Format, inputDescriptor.Format.FormatValues()) {
			return fmt.Errorf("unsupported format<%s> for input descriptor which supports: %s", submissionDescriptor.Format, strings.Join(inputDescriptor.Format.FormatValues(), ", "))
		}

		// get cred from index
		// apply path and see if it checks out!
		//submissionDescriptor.Path
	}
	return nil
}
