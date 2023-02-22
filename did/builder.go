package did

import (
	"reflect"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// contexts and types are kept to avoid having cast to/from interface{} values
type DIDDocumentBuilder struct {
	contexts []string
	types    []string
	*DIDDocument
}

const (
	DIDDocumentLDContext string = "https://w3id.org/did/v1"
	DIDDocumentType      string = "DIDDocument"
	BuilderEmptyError    string = "builder cannot be empty"
)

// Create a new DID Document Builder
func NewDIDDocumentBuilder() DIDDocumentBuilder {
	contexts := []string{DIDDocumentLDContext}
	types := []string{DIDDocumentType}
	return DIDDocumentBuilder{
		contexts: contexts,
		types:    types,
		DIDDocument: &DIDDocument{
			ID:      uuid.NewString(),
			Context: contexts,
		},
	}
}

// Builds the DID Document
func (builder *DIDDocumentBuilder) Build() (*DIDDocument, error) {
	if builder.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := builder.DIDDocument.IsValid(); err != nil {
		return nil, errors.Wrap(err, "did doc not valid")
	}

	return builder.DIDDocument, nil
}

func (builder *DIDDocumentBuilder) IsEmpty() bool {
	if builder == nil || builder.DIDDocument == nil {
		return true
	}
	return reflect.DeepEqual(builder, &DIDDocumentBuilder{})
}

func (builder *DIDDocumentBuilder) AddContext(context interface{}) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	res, err := util.InterfaceToStrings(context)
	if err != nil {
		return errors.Wrap(err, "malformed context")
	}
	uniqueContexts := util.MergeUniqueValues(builder.contexts, res)
	builder.contexts = uniqueContexts
	builder.Context = uniqueContexts
	return nil
}

func (builder *DIDDocumentBuilder) SetID(id string) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	builder.ID = id
	return nil
}

func (builder *DIDDocumentBuilder) SetAlsoKnownAs(name string) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.AlsoKnownAs = name
	return nil
}

func (builder *DIDDocumentBuilder) SetController(controller string) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.Controller = controller
	return nil
}

// Note: Not thread safe
func (builder *DIDDocumentBuilder) AddVerificationMethod(m VerificationMethod) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.VerificationMethod = append(builder.VerificationMethod, m)
	return nil
}

// Note: Not thread safe
func (builder *DIDDocumentBuilder) AddAuthentication(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.Authentication = append(builder.Authentication, m)
	return nil
}

// Note: Not thread safe
func (builder *DIDDocumentBuilder) AddAssertionMethod(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.AssertionMethod = append(builder.AssertionMethod, m)
	return nil
}

// Note: Not thread safe
func (builder *DIDDocumentBuilder) AddKeyAgreement(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.KeyAgreement = append(builder.KeyAgreement, m)
	return nil
}

// Note: Not thread safe
func (builder *DIDDocumentBuilder) AddCapabilityInvocation(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.CapabilityInvocation = append(builder.CapabilityInvocation, m)
	return nil
}

// Note: Not thread safe
func (builder *DIDDocumentBuilder) AddCapabilityDelgation(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.CapabilityDelegation = append(builder.CapabilityDelegation, m)
	return nil
}

// Note: Not thread safe
func (builder *DIDDocumentBuilder) AddService(s Service) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.Services = append(builder.Services, s)
	return nil
}
