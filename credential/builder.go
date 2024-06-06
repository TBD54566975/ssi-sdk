package credential

import (
	"fmt"
	"net/url"
	"reflect"

	"github.com/google/uuid"

	"github.com/TBD54566975/ssi-sdk/util"

	"github.com/pkg/errors"
)

const (
	VerifiableCredentialsLinkedDataContext string = "https://www.w3.org/2018/credentials/v1"
	VerifiableCredentialType               string = "VerifiableCredential"
	VerifiableCredentialIDProperty         string = "id"
	// VerifiableCredentialJSONSchemaProperty as defined by https://www.w3.org/TR/vc-json-schema/#jsonschemacredential
	VerifiableCredentialJSONSchemaProperty string = "jsonSchema"
	VerifiablePresentationType             string = "VerifiablePresentation"

	BuilderEmptyError string = "builder cannot be empty"
)

// VerifiableCredentialBuilder uses the builder pattern to construct a verifiable credential
type VerifiableCredentialBuilder struct {
	// contexts and types are kept to avoid having cast to/from any values
	contexts []string
	types    []string
	*VerifiableCredential
}

// NewVerifiableCredentialBuilder returns an initialized credential builder with some default fields populated
// Setting emptyID as True creates VC with empty ID. Default ID is a random UUID.
func NewVerifiableCredentialBuilder(emptyID ...bool) VerifiableCredentialBuilder {
	contexts := []string{VerifiableCredentialsLinkedDataContext}
	types := []string{VerifiableCredentialType}
	id := uuid.NewString()
	if len(emptyID)>0 && emptyID[0]{
		id = ""
	}
	vcb := VerifiableCredentialBuilder{
		contexts: contexts,
		types:    types,
		VerifiableCredential: &VerifiableCredential{
			ID:           id,
			Context:      contexts,
			Type:         types,
			IssuanceDate: util.GetRFC3339Timestamp(),
		},
	}
	return vcb
	
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

func (vcb *VerifiableCredentialBuilder) AddContext(context any) error {
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
    if _, err := url.Parse(id); err != nil {
		return errors.Wrap(err, "malformed id")
	}
	vcb.ID = id
	return nil
}

func (vcb *VerifiableCredentialBuilder) AddType(t any) error {
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

func (vcb *VerifiableCredentialBuilder) SetIssuer(issuer any) error {
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

func (vcb *VerifiableCredentialBuilder) SetCredentialStatus(status any) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	statusMap, err := util.ToJSONMap(status)
	if err != nil {
		return errors.Wrap(err, "status value not of required type map[string]any")
	}

	// check required properties
	if v, ok := statusMap["id"]; !ok || v == "" {
		return errors.New("status must contain an `id` property")
	}
	if v, ok := statusMap["type"]; !ok || v == "" {
		return errors.New("status must contain a `type` property")
	}

	vcb.CredentialStatus = statusMap
	return nil
}

func (vcb *VerifiableCredentialBuilder) SetCredentialSubject(subject CredentialSubject) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
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

func (vcb *VerifiableCredentialBuilder) SetEvidence(evidence []any) error {
	if vcb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	if len(evidence) == 0 {
		return errors.New("evidence cannot be empty")
	}

	vcb.Evidence = evidence
	return nil
}

// VerifiablePresentationBuilder uses the builder pattern to construct a verifiable presentation
type VerifiablePresentationBuilder struct {
	// contexts and types are kept to avoid having cast to/from any values
	contexts []string
	types    []string
	*VerifiablePresentation
}

// NewVerifiablePresentationBuilder returns an initialized credential builder with some default fields populated
func NewVerifiablePresentationBuilder() VerifiablePresentationBuilder {
	contexts := []string{VerifiableCredentialsLinkedDataContext}
	types := []string{VerifiablePresentationType}
	return VerifiablePresentationBuilder{
		contexts: contexts,
		types:    types,
		VerifiablePresentation: &VerifiablePresentation{
			ID:      uuid.NewString(),
			Context: contexts,
			Type:    types,
		},
	}
}

// Build attempts to turn a builder into a valid verifiable credential, doing some object model validation.
// Schema validation and proof generation must be done separately.
func (vpb *VerifiablePresentationBuilder) Build() (*VerifiablePresentation, error) {
	if vpb.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := vpb.VerifiablePresentation.IsValid(); err != nil {
		return nil, errors.Wrap(err, "presentation not ready to be built")
	}

	return vpb.VerifiablePresentation, nil
}

func (vpb *VerifiablePresentationBuilder) IsEmpty() bool {
	if vpb == nil || vpb.VerifiablePresentation == nil {
		return true
	}
	return reflect.DeepEqual(vpb, &VerifiablePresentationBuilder{})
}

func (vpb *VerifiablePresentationBuilder) AddContext(context any) error {
	if vpb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	res, err := util.InterfaceToStrings(context)
	if err != nil {
		return errors.Wrap(err, "malformed context")
	}
	uniqueContexts := util.MergeUniqueValues(vpb.contexts, res)
	vpb.contexts = uniqueContexts
	vpb.Context = uniqueContexts
	return nil
}

func (vpb *VerifiablePresentationBuilder) SetID(id string) error {
	if vpb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	vpb.ID = id
	return nil
}

func (vpb *VerifiablePresentationBuilder) SetHolder(holder string) error {
	if vpb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	vpb.Holder = holder
	return nil
}

func (vpb *VerifiablePresentationBuilder) AddType(t any) error {
	if vpb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	res, err := util.InterfaceToStrings(t)
	if err != nil {
		return errors.Wrap(err, "malformed type")
	}
	uniqueTypes := util.MergeUniqueValues(vpb.types, res)
	vpb.types = uniqueTypes
	vpb.Type = uniqueTypes
	return nil
}

func (vpb *VerifiablePresentationBuilder) SetPresentationSubmission(ps any) error {
	if vpb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	vpb.PresentationSubmission = ps
	return nil
}

// AddVerifiableCredentials appends the given credentials to the verifiable presentation.
// It does not check for duplicates.
func (vpb *VerifiablePresentationBuilder) AddVerifiableCredentials(creds ...any) error {
	if vpb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}
	if creds == nil {
		return errors.New("cannot set no verifiable credentials")
	}
	vpb.VerifiableCredential = append(vpb.VerifiableCredential, creds...)
	return nil
}
