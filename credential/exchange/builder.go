package exchange

import (
	"reflect"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/util"
)

const (
	BuilderEmptyError string = "builder cannot be empty"
)

type PresentationDefinitionBuilder struct {
	*PresentationDefinition
}

func NewPresentationDefinitionBuilder() PresentationDefinitionBuilder {
	return PresentationDefinitionBuilder{
		PresentationDefinition: &PresentationDefinition{
			ID: uuid.NewString(),
		},
	}
}

func (pdb *PresentationDefinitionBuilder) Build() (*PresentationDefinition, error) {
	if pdb.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := pdb.PresentationDefinition.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "presentation definition not ready to be built")
	}

	return pdb.PresentationDefinition, nil
}

func (pdb *PresentationDefinitionBuilder) IsEmpty() bool {
	if pdb == nil || pdb.PresentationDefinition.IsEmpty() {
		return true
	}
	return reflect.DeepEqual(pdb, &PresentationDefinitionBuilder{})
}

type PresentationSubmissionBuilder struct {
	*PresentationSubmission
}

func NewPresentationSubmissionBuilder(definitionID string) PresentationSubmissionBuilder {
	return PresentationSubmissionBuilder{
		PresentationSubmission: &PresentationSubmission{
			ID:           uuid.NewString(),
			DefinitionID: definitionID,
		},
	}
}

func (psb *PresentationSubmissionBuilder) Build() (*PresentationSubmission, error) {
	if psb.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := psb.PresentationSubmission.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "presentation submission not ready to be built")
	}

	return psb.PresentationSubmission, nil
}

func (psb *PresentationSubmissionBuilder) IsEmpty() bool {
	if psb == nil || psb.PresentationSubmission.IsEmpty() {
		return true
	}
	return reflect.DeepEqual(psb, &PresentationSubmissionBuilder{})
}
