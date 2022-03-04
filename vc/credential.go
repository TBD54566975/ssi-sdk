package vc

import (
	"fmt"
	"reflect"

	"github.com/google/uuid"

	"github.com/TBD54566975/did-sdk/util"

	"github.com/pkg/errors"
)

const (
	VerifiableCredentialsLinkedDataContext string = "https://www.w3.org/2018/credentials/v1"
	VerifiableCredentialType               string = "VerifiableCredential"
	VerifiableCredentialIDProperty         string = "id"

	CredentialBuilderEmptyError string = "Credential Builder cannot be empty"
)

// CredentialBuilder uses the builder pattern to construct a verifiable credential
type CredentialBuilder struct {
	// contexts and types are kept to avoid having cast to/from interface{} values
	contexts []string
	types    []string
	*VerifiableCredential
}

// NewCredentialBuilder returns an initialized credential builder with some default fields populated
func NewCredentialBuilder() CredentialBuilder {
	contexts := []string{VerifiableCredentialsLinkedDataContext}
	types := []string{VerifiableCredentialType}
	return CredentialBuilder{
		contexts: contexts,
		types:    types,
		VerifiableCredential: &VerifiableCredential{
			ID:           uuid.New().String(),
			Context:      contexts,
			Type:         types,
			IssuanceDate: util.GetRFC3339Timestamp(),
		},
	}
}

// Build attempts to turn a builder into a valid verifiable credential, doing some object model validation.
// Schema validation and proof generation must be done separately.
func (cb *CredentialBuilder) Build() (*VerifiableCredential, error) {
	if cb.IsEmpty() {
		return nil, errors.New(CredentialBuilderEmptyError)
	}

	if err := cb.VerifiableCredential.IsValid(); err != nil {
		return nil, errors.Wrap(err, "credential not ready to be built")
	}

	return cb.VerifiableCredential, nil
}

func (cb *CredentialBuilder) IsEmpty() bool {
	if cb == nil || cb.VerifiableCredential == nil {
		return true
	}
	return reflect.DeepEqual(cb, &CredentialBuilder{})
}

func (cb *CredentialBuilder) SetContext(context interface{}) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}
	res, err := util.InterfaceToStrings(context)
	if err != nil {
		return errors.Wrap(err, "malformed context")
	}
	uniqueContexts := util.MergeUniqueValues(cb.contexts, res)
	cb.contexts = uniqueContexts
	cb.Context = uniqueContexts
	return nil
}

func (cb *CredentialBuilder) SetID(id string) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}

	cb.ID = id
	return nil
}

func (cb *CredentialBuilder) SetType(t interface{}) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}
	res, err := util.InterfaceToStrings(t)
	if err != nil {
		return errors.Wrap(err, "malformed type")
	}
	uniqueTypes := util.MergeUniqueValues(cb.types, res)
	cb.types = uniqueTypes
	cb.Type = uniqueTypes
	return nil
}

func (cb *CredentialBuilder) SetIssuer(issuer interface{}) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}

	// since an issue can be a URI or an object containing an `id` property,
	// if it's not a string or string array we'll check to see if it's an object that contains an `id` property.
	res, err := util.InterfaceToStrings(issuer)
	if err == nil {
		// if the initial value was a single string we'll maintain that
		_, ok := issuer.(string)
		if len(res) == 1 && ok {
			cb.Issuer = res[0]
		} else {
			cb.Issuer = res
		}
		return nil
	}

	// check to see if it's an object that contains an `id` property
	jsonMap, err := util.ToJSONMap(issuer)
	if err != nil {
		return errors.Wrap(err, "malformed issuer")
	}
	if _, gotID := jsonMap[VerifiableCredentialIDProperty]; !gotID {
		return errors.New("issuer object did not contain `id` property")
	}
	// we know it's a valid issuer object object
	cb.Issuer = issuer
	return nil
}

func (cb *CredentialBuilder) SetIssuanceDate(dateTime string) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}

	if !util.IsRFC3339Timestamp(dateTime) {
		return fmt.Errorf("timestamp must be ISO-8601 compliant: %s", dateTime)
	}

	cb.IssuanceDate = dateTime
	return nil
}

func (cb *CredentialBuilder) SetExpirationDate(dateTime string) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}

	if !util.IsRFC3339Timestamp(dateTime) {
		return fmt.Errorf("timestamp must be ISO-8601 compliant: %s", dateTime)
	}

	cb.ExpirationDate = dateTime
	return nil
}

func (cb *CredentialBuilder) SetCredentialStatus(status CredentialStatus) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}

	if err := util.NewValidator().Struct(status); err != nil {
		return errors.Wrap(err, "credential status not valid")
	}

	cb.CredentialStatus = &status
	return nil
}

func (cb *CredentialBuilder) SetCredentialSubject(subject CredentialSubject) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}

	if subject.GetID() == "" {
		return errors.New("credential subject must have an ID property")
	}

	cb.CredentialSubject = subject
	return nil
}

func (cb *CredentialBuilder) SetCredentialSchema(schema CredentialSchema) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}

	if err := util.NewValidator().Struct(schema); err != nil {
		return errors.Wrap(err, "credential schema not valid")
	}

	cb.CredentialSchema = &schema
	return nil
}

func (cb *CredentialBuilder) SetRefreshService(refreshService RefreshService) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}

	if err := util.NewValidator().Struct(refreshService); err != nil {
		return errors.Wrap(err, "refresh service not valid")
	}

	cb.RefreshService = &refreshService
	return nil
}

func (cb *CredentialBuilder) SetTermsOfUse(terms []TermsOfUse) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}
	if len(terms) == 0 {
		return errors.New("terms of use cannot be empty")
	}

	cb.TermsOfUse = terms
	return nil
}

func (cb *CredentialBuilder) SetEvidence(evidence []interface{}) error {
	if cb.IsEmpty() {
		return errors.New(CredentialBuilderEmptyError)
	}
	if len(evidence) == 0 {
		return errors.New("evidence cannot be empty")
	}

	cb.Evidence = evidence
	return nil
}
