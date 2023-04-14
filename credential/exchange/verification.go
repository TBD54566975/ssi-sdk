package exchange

import (
	"context"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/did"
	"github.com/TBD54566975/ssi-sdk/schema"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/crypto"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"
)

// VerifyPresentationSubmission verifies a presentation submission for both signature validity and correctness
// with the specification. It is assumed that the caller knows the submission embed target, and the corresponding
// presentation definition, and has access to the public key of the signer. A DID resolver is required to resolve
// the DID and keys of the signer for each credential in the presentation, whose signatures also need to be verified.
// Note: this method does not support LD cryptosuites, and prefers JWT representations. Future refactors
// may include an analog method for LD suites.
func VerifyPresentationSubmission(verifier any, resolver did.Resolver, et EmbedTarget, def PresentationDefinition, submission []byte) error {
	if resolver == nil {
		return errors.New("resolver cannot be empty")
	}
	if err := canProcessDefinition(def); err != nil {
		return errors.Wrap(err, "not able to verify submission; feature not supported")
	}
	if !IsSupportedEmbedTarget(et) {
		return fmt.Errorf("unsupported presentation submission embed target type: %s", et)
	}
	switch et {
	case JWTVPTarget:
		jwtVerifier, ok := verifier.(crypto.JWTVerifier)
		if !ok {
			return fmt.Errorf("verifier<%T> is not a JWT verifier", verifier)
		}
		// verify the VP, which in turn verifies all credentials in it
		_, _, vp, err := credential.VerifyVerifiablePresentationJWT(context.Background(), jwtVerifier, resolver, string(submission))
		if err != nil {
			return errors.Wrap(err, "verification of the presentation submission failed")
		}
		return VerifyPresentationSubmissionVP(def, *vp)
	default:
		return fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
	}
}

// VerifyPresentationSubmissionVP verifies whether a verifiable presentation is a valid presentation submission
// for a given presentation definition. No signature verification happens here.
func VerifyPresentationSubmissionVP(def PresentationDefinition, vp credential.VerifiablePresentation) error {
	if err := vp.IsValid(); err != nil {
		return errors.Wrap(err, "presentation submission does not contain a valid VP")
	}

	// first, validate the presentation submission in the VP
	submission, err := toPresentationSubmission(vp.PresentationSubmission)
	if err != nil {
		return errors.Wrap(err, "unable to parse presentation submission from verifiable presentation")
	}
	if err = submission.IsValid(); err != nil {
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
	inputDescriptorLookup := make(map[string]InputDescriptor)
	for _, inputDescriptor := range def.InputDescriptors {
		inputDescriptorLookup[inputDescriptor.ID] = inputDescriptor
		submissionDescriptor, ok := submissionDescriptorLookup[inputDescriptor.ID]
		if !ok {
			return fmt.Errorf("unfulfilled input descriptor<%s>; submission not valid", inputDescriptor.ID)
		}

		// if the format on the submitted claim does not match the input descriptor, we cannot process
		if inputDescriptor.Format != nil && !util.Contains(submissionDescriptor.Format, inputDescriptor.Format.FormatValues()) {
			return fmt.Errorf("for input descriptor<%s>, the format of submission descriptor<%s> is not one"+
				"  of the supported formats: %s", inputDescriptor.ID, submissionDescriptor.Format,
				strings.Join(inputDescriptor.Format.FormatValues(), ", "))
		}

		// TODO(gabe) support nested paths in presentation submissions https://github.com/TBD54566975/ssi-sdk/issues/73
		if submissionDescriptor.PathNested != nil {
			return fmt.Errorf("submission with nested paths not supported: %s", submissionDescriptor.ID)
		}

		// resolve the claim from the JSON path expression in the submission descriptor
		claim, err := jsonpath.JsonPathLookup(vpJSON, submissionDescriptor.Path)
		if err != nil {
			return errors.Wrapf(err, "could not resolve claim from submission descriptor<%s> with path: %s",
				submissionDescriptor.ID, submissionDescriptor.Path)
		}

		// TODO(gabe) add in signature verification of claims here https://github.com/TBD54566975/ssi-sdk/issues/71
		_, _, cred, err := credential.ToCredential(claim)
		if err != nil {
			return errors.Wrapf(err, "getting claim as json: <%s>", claim)
		}

		// verify the submitted claim complies with the input descriptor

		// if there are no constraints, we are done checking for validity
		constraints := inputDescriptor.Constraints
		if constraints == nil {
			continue
		}

		// TODO(gabe) consider enforcing limited disclosure if present
		// for each field we need to verify at least one path matches
		credJSON, err := credential.ToCredentialJSONMap(claim)
		if err != nil {
			return errors.Wrapf(err, "getting credential as json: %v", cred)
		}
		for _, field := range constraints.Fields {
			// get data from path
			pathedDataJSON, err := getJSONDataFromPath(credJSON, field.Path)
			if err != nil && !field.Optional {
				return errors.Wrapf(err, "input descriptor<%s> not fulfilled for non-optional field: %s", inputDescriptor.ID, field.ID)
			}

			// apply json schema filter if present
			if field.Filter != nil {
				filterJSON, err := field.Filter.ToJSON()
				if err != nil && !field.Optional {
					return errors.Wrapf(err, "turning filter into JSON schema")
				}
				if err = schema.IsJSONValidAgainstSchema(pathedDataJSON, filterJSON); err != nil && !field.Optional {
					return errors.Wrapf(err, "unable to apply filter<%s> to data from path: %s", filterJSON, field.Path)
				}
			}
		}

		// check relational constraints if present
		subjectIsIssuerConstraint := constraints.SubjectIsIssuer
		if subjectIsIssuerConstraint != nil && *subjectIsIssuerConstraint == Required {
			issuer, ok := cred.Issuer.(string)
			if !ok {
				return fmt.Errorf("unable to get issuer from cred: %s", cred.Issuer)
			}
			subject, ok := cred.CredentialSubject[credential.VerifiableCredentialIDProperty]
			if !ok {
				return fmt.Errorf("unable to get subject from cred: %s", cred.CredentialSubject)
			}
			if issuer != subject {
				return fmt.Errorf("subject<%s> is not the same as issuer<%s>", subject, issuer)
			}
		}

		// TODO(gabe) is_holder and same_subject cannot yet be implemented https://github.com/TBD54566975/ssi-sdk/issues/64
		// TODO(gabe) check credential status https://github.com/TBD54566975/ssi-sdk/issues/65
	}
	return nil
}

func toPresentationSubmission(maybePresentationSubmission any) (*PresentationSubmission, error) {
	bytes, err := json.Marshal(maybePresentationSubmission)
	if err != nil {
		return nil, err
	}
	var submission PresentationSubmission
	if err = json.Unmarshal(bytes, &submission); err != nil {
		return nil, err
	}
	return &submission, nil
}

func getJSONDataFromPath(claim any, paths []string) (string, error) {
	for _, path := range paths {
		if pathedData, err := jsonpath.JsonPathLookup(claim, path); err == nil {
			pathedDataBytes, err := json.Marshal(pathedData)
			if err != nil {
				return "", errors.Wrapf(err, "marshalling pathed data<%s> to bytes", pathedData)
			}
			return string(pathedDataBytes), nil
		}
	}
	return "", errors.New("matching path for claim could not be found")
}
