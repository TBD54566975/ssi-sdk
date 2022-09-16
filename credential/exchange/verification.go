package exchange

import (
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/credential/signing"
	"github.com/TBD54566975/ssi-sdk/util"
)

// VerifyPresentationSubmission verifies a presentation submission for both signature validity and correctness
// with the specification. It is assumed that the caller knows the submission embed target, and the corresponding
// presentation definition, and has access to the public key of the signer.
// Note: this method does not support LD cryptosuites, and prefers JWT representations. Future refactors
// may include an analog method for LD suites.
func VerifyPresentationSubmission(verifier crypto.JWTVerifier, et EmbedTarget, def PresentationDefinition, submission []byte) error {
	if err := canProcessDefinition(def); err != nil {
		err := errors.Wrap(err, "feature not supported in processing given presentation definition")
		logrus.WithError(err).Error("not able to verify presentation submission")
		return err
	}
	if !IsSupportedEmbedTarget(et) {
		err := fmt.Errorf("unsupported presentation submission embed target type: %s", et)
		logrus.WithError(err).Error()
		return err
	}
	switch et {
	case JWTVPTarget:
		vp, err := signing.VerifyVerifiablePresentationJWT(verifier, string(submission))
		if err != nil {
			err := errors.Wrap(err, "verification of the presentation submission failed")
			logrus.WithError(err).Error()
			return err
		}
		return VerifyPresentationSubmissionVP(def, *vp)
	default:
		err := fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
		logrus.WithError(err).Error()
		return err
	}
}

// VerifyPresentationSubmissionVP verifies whether a verifiable presentation is a valid presentation submission
// for a given presentation definition.
// TODO(gabe) handle signature validation of submission claims https://github.com/TBD54566975/ssi-sdk/issues/71
func VerifyPresentationSubmissionVP(def PresentationDefinition, vp credential.VerifiablePresentation) error {
	if err := vp.IsValid(); err != nil {
		err := errors.Wrap(err, "presentation submission does not contain a valid VP")
		logrus.WithError(err).Error()
		return err
	}

	// first, validate the presentation submission in the VP
	submission, err := toPresentationSubmission(vp.PresentationSubmission)
	if err != nil {
		err := errors.Wrap(err, "unable to parse presentation submission from verifiable presentation")
		logrus.WithError(err).Error()
		return err
	}
	if err := submission.IsValid(); err != nil {
		err := errors.Wrap(err, "invalid presentation submission in provided verifiable presentation")
		logrus.WithError(err).Error()
		return err
	}
	if submission.DefinitionID != def.ID {
		err := fmt.Errorf("mismatched between presentation definition ID<%s> and submission's definition ID<%s>",
			def.ID, submission.DefinitionID)
		logrus.WithError(err).Error()
		return err
	}

	// index submission descriptors by id of the input descriptor
	submissionDescriptorLookup := make(map[string]SubmissionDescriptor)
	for _, d := range submission.DescriptorMap {
		submissionDescriptorLookup[d.ID] = d
	}

	// turn the vp into JSON so we can use the paths from the submission descriptor to resolve each claim
	vpJSON, err := util.ToJSONMap(vp)
	if err != nil {
		err := errors.Wrap(err, "could not turn VP into JSON representation")
		logrus.WithError(err).Error()
		return err
	}

	// validate each input descriptor is fulfilled
	for _, inputDescriptor := range def.InputDescriptors {
		submissionDescriptor, ok := submissionDescriptorLookup[inputDescriptor.ID]
		if !ok {
			err := fmt.Errorf("unfulfilled input descriptor<%s>; submission not valid", inputDescriptor.ID)
			logrus.WithError(err).Error()
			return err
		}

		// if the format on the submitted claim does not match the input descriptor, we cannot process
		if inputDescriptor.Format != nil && !util.Contains(submissionDescriptor.Format, inputDescriptor.Format.FormatValues()) {
			return fmt.Errorf("for input descriptor<%s>, the format of submission descriptor<%s> is not one"+
				"  of the supported formats: %s", inputDescriptor.ID, submissionDescriptor.Format,
				strings.Join(inputDescriptor.Format.FormatValues(), ", "))
		}

		// TODO(gabe) support nested paths in presentation submissions
		// https://github.com/TBD54566975/ssi-sdk/issues/73
		if submissionDescriptor.PathNested != nil {
			err := fmt.Errorf("submission with nested paths not supported: %s", submissionDescriptor.ID)
			logrus.WithError(err).Error()
			return err
		}

		// resolve the claim from the JSON path expression in the submission descriptor
		submittedClaim, err := jsonpath.JsonPathLookup(vpJSON, submissionDescriptor.Path)
		if err != nil {
			err := errors.Wrapf(err, "could not resolve claim from submission descriptor<%s> with path: %s",
				submissionDescriptor.ID, submissionDescriptor.Path)
			logrus.WithError(err).Error()
			return err
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
				err := errors.Wrapf(err, "input descriptor<%s> not fulfilled for field: %s", inputDescriptor.ID, field.ID)
				logrus.WithError(err).Error()
				return err
			}
		}
	}
	return nil
}

func toPresentationSubmission(maybePresentationSubmission interface{}) (*PresentationSubmission, error) {
	bytes, err := json.Marshal(maybePresentationSubmission)
	if err != nil {
		return nil, err
	}
	var submission PresentationSubmission
	if err := json.Unmarshal(bytes, &submission); err != nil {
		return nil, err
	}
	return &submission, nil
}

func findMatchingPath(claim interface{}, paths []string) error {
	for _, path := range paths {
		if _, err := jsonpath.JsonPathLookup(claim, path); err == nil {
			return nil
		}
	}
	err := errors.New("matching path for claim could not be found")
	logrus.WithError(err).Error()
	return err
}
