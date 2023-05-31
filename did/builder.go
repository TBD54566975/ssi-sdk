package did

import (
	"reflect"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/util"
)

// DocumentBuilder contexts and types are kept to avoid having cast to/from any values
type DocumentBuilder struct {
	contexts []string
	types    []string
	*Document
}

const (
	DIDDocumentLDContext string = "https://w3id.org/did/v1"
	DIDDocumentType      string = "Document"
	BuilderEmptyError    string = "builder cannot be empty"
)

// NewDIDDocumentBuilder Creates a new DID Document Builder
func NewDIDDocumentBuilder() DocumentBuilder {
	contexts := []string{DIDDocumentLDContext}
	types := []string{DIDDocumentType}
	return DocumentBuilder{
		contexts: contexts,
		types:    types,
		Document: &Document{
			ID:      uuid.NewString(),
			Context: contexts,
		},
	}
}

// Build builds the DID Document
func (builder *DocumentBuilder) Build() (*Document, error) {
	if builder.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := builder.Document.IsValid(); err != nil {
		return nil, errors.Wrap(err, "did doc not valid")
	}

	return builder.Document, nil
}

func (builder *DocumentBuilder) IsEmpty() bool {
	if builder == nil || builder.Document == nil {
		return true
	}
	return reflect.DeepEqual(builder, &DocumentBuilder{})
}

func (builder *DocumentBuilder) AddContext(context any) error {
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

func (builder *DocumentBuilder) SetID(id string) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	builder.ID = id
	return nil
}

func (builder *DocumentBuilder) SetAlsoKnownAs(name string) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.AlsoKnownAs = name
	return nil
}

func (builder *DocumentBuilder) SetController(controller string) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.Controller = controller
	return nil
}

// AddVerificationMethod Note: Not thread safe
func (builder *DocumentBuilder) AddVerificationMethod(m VerificationMethod) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.VerificationMethod = append(builder.VerificationMethod, m)
	return nil
}

// AddAuthenticationMethod Note: Not thread safe
func (builder *DocumentBuilder) AddAuthenticationMethod(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.Authentication = append(builder.Authentication, m)
	return nil
}

// AddAssertionMethod Note: Not thread safe
func (builder *DocumentBuilder) AddAssertionMethod(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.AssertionMethod = append(builder.AssertionMethod, m)
	return nil
}

// AddKeyAgreement Note: Not thread safe
func (builder *DocumentBuilder) AddKeyAgreement(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.KeyAgreement = append(builder.KeyAgreement, m)
	return nil
}

// AddCapabilityInvocation Note: Not thread safe
func (builder *DocumentBuilder) AddCapabilityInvocation(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.CapabilityInvocation = append(builder.CapabilityInvocation, m)
	return nil
}

// AddCapabilityDelegation Note: Not thread safe
func (builder *DocumentBuilder) AddCapabilityDelegation(m VerificationMethodSet) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.CapabilityDelegation = append(builder.CapabilityDelegation, m)
	return nil
}

// AddService Note: Not thread safe
func (builder *DocumentBuilder) AddService(s Service) error {
	if builder.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	builder.Services = append(builder.Services, s)
	return nil
}
