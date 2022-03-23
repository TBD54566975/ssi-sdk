package exchange

import (
	"fmt"
	"github.com/TBD54566975/did-sdk/credential"
	"github.com/TBD54566975/did-sdk/credential/signing"
	"github.com/TBD54566975/did-sdk/cryptosuite"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"reflect"
)

// EmbedTarget describes where a presentation_submission is located in an object model
// https://identity.foundation/presentation-exchange/#embed-targets
type EmbedTarget string

const (
	// JWTVPTarget is an embed target where a presentation submission is represented alongside a Verifiable Presentation
	// in a JWT value. `presentation_submission` is a top-level claim alongside `vc` for the VP
	JWTVPTarget EmbedTarget = "jwt_vp"
	//JWTTarget   EmbedTarget = "jwt"
	//LDPVPTarget EmbedTarget = "ldp_vp"

	PresentationSubmissionContext string = "https://identity.foundation/presentation-exchange/submission/v1"
	PresentationSubmissionType    string = "PresentationSubmission"
)

// PresentationClaim 's may be of any claim format designation, including LD or JWT variations of VCs or VPs
// https://identity.foundation/presentation-exchange/#claim-format-designations
type PresentationClaim struct {
	Credential   *credential.VerifiableCredential
	Presentation *credential.VerifiablePresentation
	Token        *string
	Format       ClaimFormat
}

func (pc *PresentationClaim) IsEmpty() bool {
	if pc == nil || (pc.Credential == nil && pc.Presentation == nil && pc.Token == nil) {
		return true
	}
	return reflect.DeepEqual(pc, &PresentationClaim{})
}

// GetClaimValue returns the value of the claim, since PresentationClaim is a union type. An error is returned if
// no value is present in any of the possible embedded types.
func (pc *PresentationClaim) GetClaimValue() (interface{}, error) {
	if pc.Credential != nil {
		return *pc.Credential, nil
	}
	if pc.Presentation != nil {
		return *pc.Presentation, nil
	}
	if pc.Token != nil {
		return *pc.Token, nil
	}
	return nil, errors.New("claim is empty")
}

// processedClaim represents a claim that has been processed for an input descriptor along with relevant
// information for building a valid descriptor_map in the resulting presentation submission
type processedClaim struct {
	PresentationClaim
	SubmissionDescriptor
}

// BuildPresentationSubmission constructs a submission given a presentation definition, set of claims, and an
// embed target format.
// https://identity.foundation/presentation-exchange/#presentation-submission
func BuildPresentationSubmission(signer cryptosuite.Signer, def PresentationDefinition, claims []PresentationClaim, et EmbedTarget) ([]byte, error) {
	if !IsSupportedEmbedTarget(et) {
		return nil, fmt.Errorf("unsupported presentation submission embed target type: %s", et)
	}
	switch et {
	case JWTVPTarget:
		jwkSigner, ok := signer.(*cryptosuite.JSONWebKeySigner)
		if !ok {
			return nil, fmt.Errorf("signer not valid for request type: %s", et)
		}
		vpSubmission, err := BuildPresentationSubmissionVP(def, claims)
		if err != nil {
			return nil, errors.Wrap(err, "unable to fulfill presentation definition with given credentials")
		}
		return signing.SignVerifiablePresentationJWT(*jwkSigner, *vpSubmission)
	default:
		return nil, fmt.Errorf("presentation submission embed target <%s> is not implemented", et)
	}
}

// BuildPresentationSubmissionVP takes a presentation definition and a set of claims. According to the presentation
// definition, and the algorithm defined - https://identity.foundation/presentation-exchange/#input-evaluation - in
// the specification, a presentation submission is constructed as a Verifiable Presentation.
func BuildPresentationSubmissionVP(def PresentationDefinition, claims []PresentationClaim) (*credential.VerifiablePresentation, error) {
	if err := canProcessDefinition(def); err != nil {
		return nil, errors.Wrap(err, "feature not supported in processing given presentation definition")
	}
	builder := credential.NewVerifiablePresentationBuilder()
	if err := builder.AddContext(PresentationSubmissionContext); err != nil {
		return nil, err
	}
	if err := builder.AddType(PresentationSubmissionType); err != nil {
		return nil, err
	}

	submission := PresentationSubmission{
		ID:           uuid.New().String(),
		DefinitionID: def.ID,
	}

	// begin to process to presentation definition against the available claims
	var processedClaims []processedClaim
	for _, id := range def.InputDescriptors {
		processedClaim, err := processInputDescriptor(id, claims)
		if err != nil {
			return nil, errors.Wrapf(err, "error processing input descriptor: %s", id.ID)
		}
		if processedClaim != nil {
			processedClaims = append(processedClaims, *processedClaim)
		} else {
			return nil, fmt.Errorf("input descrpitor<%s> could not be fulfilled; could not build a valid presentation submission", id.ID)
		}
	}

	// set descriptor map in submission and credentials to the VP
	var descriptorMap []SubmissionDescriptor
	for _, claim := range processedClaims {
		descriptorMap = append(descriptorMap, claim.SubmissionDescriptor)
		claimValue, err := claim.GetClaimValue()
		if err != nil {
			return nil, errors.Wrap(err, "could not build submission descriptor in presentation submission")
		}
		if err := builder.AddVerifiableCredentials(claimValue); err != nil {
			return nil, errors.Wrap(err, "could not add claim value to verifiable presentation")
		}
	}

	// set submission in vp, build, and return
	if err := builder.SetPresentationSubmission(submission); err != nil {
		return nil, err
	}
	return builder.Build()
}

// processInputDescriptor runs the input evaluation algorithm described in the spec for a specific input descriptor
// https://identity.foundation/presentation-exchange/#input-evaluation
// TODO(gabe) consider normalization of claims before processing
func processInputDescriptor(id InputDescriptor, claims []PresentationClaim) (*processedClaim, error) {
	constraints := id.Constraints
	fields := constraints.Fields
	if !(constraints == nil || len(fields) == 0) {
		return nil, fmt.Errorf("invalid input descriptor without constraints and/or fields: %s", id.ID)
	}

	// for the input descriptor to be successfully processed each field needs to yield a result for a given claim,
	// so we need to iterate through each claim, and test it against each field, and each path within each field.
	// if we find a match, we know a claim can fulfill the given input descriptor.
	fieldsToProcess := len(fields)
	limitDisclosure := false
	disclosure := constraints.LimitDisclosure
	if disclosure != nil && (*disclosure == Required || *disclosure == Preferred) {
		limitDisclosure = true
	}
	for _, claim := range claims {
		var processedClaims []processedClaim
		for _, field := range fields {
			// if we were able to process a field for a given claim, we'll attempt to process the proceeding field
			limitedClaim, fulfilled := processInputDescriptorField(field, limitDisclosure, claim)
			if fulfilled && limitDisclosure {
				processedClaims = append(processedClaims, *limitedClaim)
			}
		}

		// if a claim has matched all fields, we can fulfill the input descriptor with this claim
		// because the `limit_disclosure` property may have been present, we must merge the claim values we've
		// processed in order of processing.
		if len(processedClaims) == fieldsToProcess {
			// need to merge limited claims
			var claim *processedClaim
			var err error
			if limitDisclosure {

			} else {
				
			}
			return claim, err
		}
	}
	return nil, fmt.Errorf("no claims could fulfill the input descriptor: %s", id.ID)
}

// processInputDescriptorField applies all possible path values to a claim, and checks to see if any match.
// if a path matches fulfilled will be set to true and no limitedClaim value will be returned. if limitDisclosure is
// set to true, the limitedClaim value will be returned as well.
func processInputDescriptorField(field Field, limitDisclosure bool, claim PresentationClaim) (limitedClaim *processedClaim, fulfilled bool) {
	for _, path := range field.Path {

	}
}

// TODO(gabe) https://github.com/TBD54566975/did-sdk/issues/56
// check for certain features we may not support yet: submission requirements, predicates, relational constraints,
// credential status, JSON-LD framing from https://identity.foundation/presentation-exchange/#features
func canProcessDefinition(def PresentationDefinition) error {
	submissionRequirementsErr := "submission requirements feature not supported"
	if len(def.SubmissionRequirements) > 0 {
		return errors.New(submissionRequirementsErr)
	}
	for _, id := range def.InputDescriptors {
		if id.Constraints != nil {
			if len(id.Group) > 0 {
				return errors.New(submissionRequirementsErr)
			}
			if len(id.Constraints.Fields) > 0 {
				for _, field := range id.Constraints.Fields {
					if field.Predicate != nil || field.Filter != nil {
						return errors.New("predicate feature not supported")
					}
				}
			}
		}
	}
	for _, id := range def.InputDescriptors {
		constraints := id.Constraints
		if constraints != nil && len(constraints.Fields) > 0 && constraints.IsHolder != nil ||
			constraints.SameSubject != nil || constraints.SubjectIsIssuer != nil {
			return errors.New("relational constraint feature not supported")
		}
	}
	for _, id := range def.InputDescriptors {
		if id.Constraints != nil && len(id.Constraints.Fields) > 0 && id.Constraints.Statuses != nil {
			return errors.New("credential status constraint feature not supported")
		}
	}
	if def.Frame != nil {
		return errors.New("JSON-LD framing feature not supported")
	}
	return nil
}

func VerifyPresentationSubmission() error {
	return nil
}

func IsSupportedEmbedTarget(et EmbedTarget) bool {
	supported := GetSupportedEmbedTargets()
	for _, t := range supported {
		if et == t {
			return true
		}
	}
	return false
}

func GetSupportedEmbedTargets() []EmbedTarget {
	return []EmbedTarget{JWTVPTarget}
}
