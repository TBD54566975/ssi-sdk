package did

import (
	"reflect"

	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

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
		return nil, errors.Wrap(err, "did not ready to be built")
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
