package credential

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

	BuilderEmptyError string = "builder cannot be empty"
)

// VerifiableCredentialBuilder uses the builder pattern to construct a verifiable credential
type VerifiableCredentialBuilder struct {
	// contexts and types are kept to avoid having cast to/from interface{} values
	contexts []string
	types    []string
	*VerifiableCredential
}

// NewVerifiableCredentialBuilder returns an initialized credential builder with some default fields populated
func NewVerifiableCredentialBuilder() VerifiableCredentialBuilder {
	contexts := []string{VerifiableCredentialsLinkedDataContext}
	types := []string{VerifiableCredentialType}
	return VerifiableCredentialBuilder{
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
func (vcb *VerifiableCredentialBuilder) Build() (*VerifiableCredential, error) {
	if vcb.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := vcb.VerifiableCredential.IsValid(); err != nil {
		return nil, errors.Wrap(err, "credential not ready to be built")
	}

	return vcb.VerifiableCredential, nil
}

func (vcb *VerifiableCredentialBuilder) IsEmpty() bool {
	if vcb == nil || vcb.VerifiableCredential == nil {
		return true
	}
	return reflect.DeepEqual(vcb, &VerifiableCredentialBuilder{})
}

func (vcb *VerifiableCredentialBuilder) SetContext(context interface{}) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	res, err := util.InterfaceToStrings(context)
	if err != nil {
		return errors.Wrap(err, "malformed context")
	}
	uniqueContexts := util.MergeUniqueValues(vcb.contexts, res)
	vcb.contexts = uniqueContexts
	vcb.Context = uniqueContexts
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetID(id string) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	vcb.ID = id
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetType(t interface{}) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	res, err := util.InterfaceToStrings(t)
	if err != nil {
		return errors.Wrap(err, "malformed type")
	}
	uniqueTypes := util.MergeUniqueValues(vcb.types, res)
	vcb.types = uniqueTypes
	vcb.Type = uniqueTypes
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetIssuer(issuer interface{}) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	// since an issue can be a URI or an object containing an `id` property,
	// if it's not a string or string array we'll check to see if it's an object that contains an `id` property.
	res, err := util.InterfaceToStrings(issuer)
	if err == nil {
		// if the initial value was a single string we'll maintain that
		_, ok := issuer.(string)
		if len(res) == 1 && ok {
			vcb.Issuer = res[0]
		} else {
			vcb.Issuer = res
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
	vcb.Issuer = issuer
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetIssuanceDate(dateTime string) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if !util.IsRFC3339Timestamp(dateTime) {
		return fmt.Errorf("timestamp must be ISO-8601 compliant: %s", dateTime)
	}

	vcb.IssuanceDate = dateTime
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetExpirationDate(dateTime string) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if !util.IsRFC3339Timestamp(dateTime) {
		return fmt.Errorf("timestamp must be ISO-8601 compliant: %s", dateTime)
	}

	vcb.ExpirationDate = dateTime
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetCredentialStatus(status CredentialStatus) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if err := util.NewValidator().Struct(status); err != nil {
		return errors.Wrap(err, "credential status not valid")
	}

	vcb.CredentialStatus = &status
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetCredentialSubject(subject CredentialSubject) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if subject.GetID() == "" {
		return errors.New("credential subject must have an ID property")
	}

	vcb.CredentialSubject = subject
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetCredentialSchema(schema CredentialSchema) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if err := util.NewValidator().Struct(schema); err != nil {
		return errors.Wrap(err, "credential schema not valid")
	}

	vcb.CredentialSchema = &schema
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetRefreshService(refreshService RefreshService) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if err := util.NewValidator().Struct(refreshService); err != nil {
		return errors.Wrap(err, "refresh service not valid")
	}

	vcb.RefreshService = &refreshService
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetTermsOfUse(terms []TermsOfUse) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	if len(terms) == 0 {
		return errors.New("terms of use cannot be empty")
	}

	vcb.TermsOfUse = terms
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetEvidence(evidence []interface{}) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	if len(evidence) == 0 {
		return errors.New("evidence cannot be empty")
	}

	vcb.Evidence = evidence
	return nil
}
