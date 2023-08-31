package exchange

import (
	"context"
	"fmt"
	"strings"

	"github.com/TBD54566975/ssi-sdk/credential/integrity"
	"github.com/TBD54566975/ssi-sdk/credential/parsing"
	"github.com/TBD54566975/ssi-sdk/crypto/jwx"
	"github.com/TBD54566975/ssi-sdk/did/resolution"
	"github.com/TBD54566975/ssi-sdk/schema"

	"github.com/goccy/go-json"
	"github.com/oliveagle/jsonpath"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/credential"
	"github.com/TBD54566975/ssi-sdk/util"
)

// VerifiedSubmissionData is the result of a successful verification of a presentation submission
// corresponds to the data that was verified, and the filtered data that was used to verify it for a given
// input descriptor
type VerifiedSubmissionData struct {
	// The ID of the input descriptor that was verified
	InputDescriptorID string
	// The raw claim data that was verified – could be a JWT, or a VC, or a VP
	Claim any
	// The filtered data as a JSON string
	FilteredData any
}

// VerifyPresentationSubmission verifies a presentation submission for both signature validity and correctness
// with the specification. It is assumed that the caller knows the submission embed target, and the corresponding
// presentation definition, and has access to the public key of the signer. A DID resolution is required to resolve
// the DID and keys of the signer for each credential in the presentation, whose signatures also need to be verified.
// Note: this method does not support LD cryptosuites, and prefers JWT representations. Future refactors
// may include an analog method for LD suites.
// TODO(gabe) remove embed target, have it detected from the submission
func VerifyPresentationSubmission(ctx context.Context, verifier any, resolver resolution.Resolver, et EmbedTarget, def PresentationDefinition, submission []byte) ([]VerifiedSubmissionData, error) { //revive:disable-line
	if resolver == nil {
		return nil, errors.New("resolution cannot be empty")
	}
	if len(submission) == 0 {
		return nil, errors.New("submission cannot be empty")
	}
	if err := canProcessDefinition(def); err != nil {
		return nil, errors.Wrap(err, "not able to verify submission; feature not supported")
	}
	if !IsSupportedEmbedTarget(et) {
		return nil, fmt.Errorf("unsupported presentation submission embed target type: %s", et)
	}
	switch et {
	case JWTVPTarget:
		jwtVerifier, ok := verifier.(jwx.Verifier)
		if !ok {
			return nil, fmt.Errorf("verifier<%T> is not a JWT verifier", verifier)
		}
		// verify the VP, which in turn verifies all credentials in it
		_, _, vp, err := integrity.VerifyVerifiablePresentationJWT(ctx, jwtVerifier, resolver, string(submission))
		if err != nil {
			return nil, errors.Wrap(err, "verification of the presentation submission failed")
		}
		return VerifyPresentationSubmissionVP(def, *vp)
	default:
		return nil, fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
	}
}

// VerifyPresentationSubmissionVP verifies whether a verifiable presentation is a valid presentation submission
// for a given presentation definition. No signature verification happens here.
func VerifyPresentationSubmissionVP(def PresentationDefinition, vp credential.VerifiablePresentation) ([]VerifiedSubmissionData, error) {
	if err := vp.IsValid(); err != nil {
		return nil, errors.Wrap(err, "presentation submission does not contain a valid VP")
	}

	// first, validate the presentation submission in the VP
	submission, err := toPresentationSubmission(vp.PresentationSubmission)
	if err != nil {
		return nil, errors.Wrap(err, "unable to parse presentation submission from verifiable presentation")
	}
	if err = submission.IsValid(); err != nil {
		return nil, errors.Wrap(err, "invalid presentation submission in provided verifiable presentation")
	}
	if submission.DefinitionID != def.ID {
		return nil, fmt.Errorf("mismatched between presentation definition ID<%s> and submission's definition ID<%s>",
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
		return nil, errors.Wrap(err, "turning VP into JSON representation")
	}

	// store results for each input descriptor
	verifiedSubmissionData := make([]VerifiedSubmissionData, 0)

	// validate each input descriptor is fulfilled
	inputDescriptorLookup := make(map[string]InputDescriptor)
	for _, inputDescriptor := range def.InputDescriptors {
		inputDescriptorID := inputDescriptor.ID

		// build verifiedSubmissionDatum should the input descriptor be fulfilled
		verifiedSubmissionDatum := VerifiedSubmissionData{InputDescriptorID: inputDescriptorID}

		inputDescriptorLookup[inputDescriptorID] = inputDescriptor
		submissionDescriptor, ok := submissionDescriptorLookup[inputDescriptorID]
		if !ok {
			return nil, fmt.Errorf("unfulfilled input descriptor<%s>; submission not valid", inputDescriptorID)
		}

		// if the format on the submitted claim does not match the input descriptor, we cannot process
		if inputDescriptor.Format != nil && !util.Contains(submissionDescriptor.Format, inputDescriptor.Format.FormatValues()) {
			return nil, fmt.Errorf("for input descriptor<%s>, the format of submission descriptor<%s> is not one"+
				"  of the supported formats: %s", inputDescriptorID, submissionDescriptor.Format,
				strings.Join(inputDescriptor.Format.FormatValues(), ", "))
		}

		// TODO(gabe) support nested paths in presentation submissions https://github.com/TBD54566975/ssi-sdk/issues/73
		if submissionDescriptor.PathNested != nil {
			return nil, fmt.Errorf("submission with nested paths not supported: %s", submissionDescriptor.ID)
		}

		// resolve the claim from the JSON path expression in the submission descriptor
		claim, err := jsonpath.JsonPathLookup(vpJSON, submissionDescriptor.Path)
		if err != nil {
			return nil, errors.Wrapf(err, "could not resolve claim from submission descriptor<%s> with path: %s",
				submissionDescriptor.ID, submissionDescriptor.Path)
		}

		// get the credential from the claim
		_, _, cred, err := parsing.ToCredential(claim)
		if err != nil {
			return nil, errors.Wrapf(err, "getting claim as json: <%s>", claim)
		}

		// verify the submitted claim complies with the input descriptor

		// if there are no constraints, we are done checking for validity
		constraints := inputDescriptor.Constraints
		if constraints == nil {
			continue
		}

		// TODO(gabe) consider enforcing limited disclosure if present
		// for each field we need to verify at least one path matches
		credJSON, err := parsing.ToCredentialJSONMap(claim)
		if err != nil {
			return nil, errors.Wrapf(err, "getting credential as json: %v", cred)
		}
		for _, field := range constraints.Fields {
			// get data from path
			pathedData, err := getDataFromJSONPath(credJSON, field.Path)
			if err != nil && !field.Optional {
				return nil, errors.Wrapf(err, "input descriptor<%s> not fulfilled for non-optional field: %s", inputDescriptorID, field.ID)
			}

			// apply json schema filter if present
			if field.Filter != nil {
				filterJSON, err := field.Filter.ToJSON()
				if err != nil && !field.Optional {
					return nil, errors.Wrapf(err, "turning filter into JSON schema")
				}
				if err = schema.IsAnyValidAgainstJSONSchema(pathedData, filterJSON); err != nil && !field.Optional {
					return nil, errors.Wrapf(err, "unable to apply filter<%s> to data from path: %s", filterJSON, field.Path)
				}
			}

			// add claim and pathed data to the verifiedSubmissionDatum once we know it is valid
			verifiedSubmissionDatum.Claim = claim
			verifiedSubmissionDatum.FilteredData = pathedData
		}

		// check relational constraints if present
		subjectIsIssuerConstraint := constraints.SubjectIsIssuer
		if subjectIsIssuerConstraint != nil && *subjectIsIssuerConstraint == Required {
			issuer, ok := cred.Issuer.(string)
			if !ok {
				return nil, fmt.Errorf("unable to get issuer from cred: %s", cred.Issuer)
			}
			subject, ok := cred.CredentialSubject[credential.VerifiableCredentialIDProperty]
			if !ok {
				return nil, fmt.Errorf("unable to get subject from cred: %s", cred.CredentialSubject)
			}
			if issuer != subject {
				return nil, fmt.Errorf("subject<%s> is not the same as issuer<%s>", subject, issuer)
			}
		}

		// once we get here we know the input descriptor is satisfied, and we can append the filtered
		// data to the value being returned
		verifiedSubmissionData = append(verifiedSubmissionData, verifiedSubmissionDatum)

		// TODO(gabe) is_holder and same_subject cannot yet be implemented https://github.com/TBD54566975/ssi-sdk/issues/64
		// TODO(gabe) check credential status https://github.com/TBD54566975/ssi-sdk/issues/65
	}
	return verifiedSubmissionData, nil
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

func getDataFromJSONPath(claim any, paths []string) (any, error) {
	for _, path := range paths {
		if pathedData, err := jsonpath.JsonPathLookup(claim, path); err == nil {
			return pathedData, nil
		}
	}
	return "", errors.New("matching path for claim could not be found")
}
