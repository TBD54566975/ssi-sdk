package exchange

import (
    "fmt"
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

func (pdb *PresentationDefinitionBuilder) SetInputDescriptors(descriptors []InputDescriptor) error {
    if pdb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if len(descriptors) == 0 {
        return errors.New("cannot set no input descriptors")
    }

    // validate all descriptors, fail if >= 1 is invalid
    // track which descriptor ids have been since, since they must be unique within the definition
    seenIDs := make(map[string]bool)
    for _, descriptor := range descriptors {
        if err := util.IsValidStruct(descriptor); err != nil {
            return errors.Wrapf(err, "cannot set input descriptors; invalid descriptor: %+v", descriptor)
        }
        if _, ok := seenIDs[descriptor.ID]; ok {
            return fmt.Errorf("cannot set input descriptors, id<%s> duplicated", descriptor.ID)
        }
        seenIDs[descriptor.ID] = true
    }

    pdb.InputDescriptors = descriptors
    return nil
}

func (pdb *PresentationDefinitionBuilder) SetName(name string) error {
    if pdb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if name == "" {
        return errors.New("cannot set empty name")
    }

    pdb.Name = name
    return nil
}

func (pdb *PresentationDefinitionBuilder) SetPurpose(purpose string) error {
    if pdb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if purpose == "" {
        return errors.New("cannot set empty purpose")
    }

    pdb.Purpose = purpose
    return nil
}

func (pdb *PresentationDefinitionBuilder) SetClaimFormat(format ClaimFormat) error {
    if pdb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if len(format.FormatValues()) == 0 {
        return errors.New("cannot set claim format with no values")
    }

    if err := util.IsValidStruct(format); err != nil {
        return errors.Wrapf(err, "cannot set invalid claim format: %+v", format)
    }

    pdb.Format = &format
    return nil
}

func (pdb *PresentationDefinitionBuilder) SetSubmissionRequirements(requirements []SubmissionRequirement) error {
    if pdb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if len(requirements) == 0 {
        return errors.New("cannot set no submission requirements")
    }

    // validate all requirements, fail if >= 1 is invalid
    for _, requirement := range requirements {
        if err := util.IsValidStruct(requirement); err != nil {
            return errors.Wrapf(err, "cannot set submission requirements; invalid requirement: %+v", requirement)
        }
    }

    pdb.SubmissionRequirements = requirements
    return nil
}

func (pdb *PresentationDefinitionBuilder) SetFrame(frame interface{}) error {
    if pdb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if frame == nil {
        return errors.New("cannot set empty frame")
    }

    pdb.Frame = frame
    return nil
}

type InputDescriptorBuilder struct {
    *InputDescriptor
}

func NewInputDescriptorBuilder() InputDescriptorBuilder {
    return InputDescriptorBuilder{
        InputDescriptor: &InputDescriptor{
            ID: uuid.NewString(),
        },
    }
}

func (idb *InputDescriptorBuilder) Build() (*InputDescriptor, error) {
    if idb.IsEmpty() {
        return nil, errors.New(BuilderEmptyError)
    }

    if err := idb.InputDescriptor.IsValid(); err != nil {
        return nil, util.LoggingErrorMsg(err, "input descriptor not ready to be built")
    }

    return idb.InputDescriptor, nil
}

func (idb *InputDescriptorBuilder) IsEmpty() bool {
    if idb == nil || idb.InputDescriptor.IsEmpty() {
        return true
    }
    return reflect.DeepEqual(idb, &InputDescriptorBuilder{})
}

func (idb *InputDescriptorBuilder) SetName(name string) error {
    if idb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if name == "" {
        return errors.New("cannot set empty name")
    }

    idb.Name = name
    return nil
}

func (idb *InputDescriptorBuilder) SetPurpose(purpose string) error {
    if idb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if purpose == "" {
        return errors.New("cannot set empty purpose")
    }

    idb.Purpose = purpose
    return nil
}

func (idb *InputDescriptorBuilder) SetClaimFormat(format ClaimFormat) error {
    if idb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if len(format.FormatValues()) == 0 {
        return errors.New("cannot set claim format with no values")
    }

    if err := util.IsValidStruct(format); err != nil {
        return errors.Wrapf(err, "cannot set invalid claim format: %+v", format)
    }

    idb.Format = &format
    return nil
}

func (idb *InputDescriptorBuilder) SetConstraints(constraints Constraints) error {
    if idb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if err := util.IsValidStruct(constraints); err != nil {
        return errors.Wrapf(err, "cannot set invalid constraints: %+v", constraints)
    }

    idb.Constraints = &constraints
    return nil
}

func (idb *InputDescriptorBuilder) SetGroup(group []string) error {
    if idb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if len(group) == 0 {
        return errors.New("cannot set empty group")
    }

    idb.Group = group
    return nil
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

func (psb *PresentationSubmissionBuilder) SetDescriptorMap(descriptors []SubmissionDescriptor) error {
    if psb.IsEmpty() {
        return errors.New(BuilderEmptyError)
    }

    if len(descriptors) == 0 {
        return errors.New("cannot set empty descriptors")
    }

    // validate all descriptors, fail if >= 1 is invalid
    for _, descriptor := range descriptors {
        if err := util.IsValidStruct(descriptor); err != nil {
            return errors.Wrapf(err, "cannot set descriptor map; invalid submission descriptor: %+v", descriptor)
        }
    }

    psb.DescriptorMap = descriptors
    return nil
}
