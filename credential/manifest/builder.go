package manifest

import (
	"reflect"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/util"
)

const (
	BuilderEmptyError string = "builder cannot be empty"
	SpecVersion       string = "https://identity.foundation/credential-manifest/spec/v1.0.0/"
)

type CredentialManifestBuilder struct {
	*CredentialManifest
}

func NewCredentialManifestBuilder() CredentialManifestBuilder {
	return CredentialManifestBuilder{
		CredentialManifest: &CredentialManifest{
			ID:          uuid.NewString(),
			SpecVersion: SpecVersion,
		},
	}
}

func (cmb *CredentialManifestBuilder) Build() (*CredentialManifest, error) {
	if cmb.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := cmb.CredentialManifest.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "credential manifest not ready to be built")
	}

	return cmb.CredentialManifest, nil
}

func (cmb *CredentialManifestBuilder) IsEmpty() bool {
	if cmb == nil || cmb.CredentialManifest.IsEmpty() {
		return true
	}
	return reflect.DeepEqual(cmb, &CredentialManifestBuilder{})
}

func (cmb *CredentialManifestBuilder) SetIssuer(i Issuer) error {
	if cmb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if err := util.IsValidStruct(i); err != nil {
		return errors.Wrap(err, "cannot set invalid issuer")
	}

	cmb.Issuer = i
	return nil
}

func (cmb *CredentialManifestBuilder) SetOutputDescriptors(descriptors []OutputDescriptor) error {
	if cmb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if len(descriptors) == 0 {
		return errors.New("cannot set no output descriptors")
	}

	// validate all descriptors, fail if >= 1 is invalid
	for _, descriptor := range descriptors {
		if err := util.IsValidStruct(descriptor); err != nil {
			return errors.Wrapf(err, "cannot set output descriptors; invalid descriptor: %+v", descriptor)
		}
	}

	cmb.OutputDescriptors = descriptors
	return nil
}

func (cmb *CredentialManifestBuilder) SetClaimFormat(format exchange.ClaimFormat) error {
	if cmb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if len(format.FormatValues()) == 0 {
		return errors.New("cannot set claim format with no values")
	}

	if err := util.IsValidStruct(format); err != nil {
		return errors.Wrapf(err, "cannot set invalid claim format: %+v", format)
	}

	cmb.Format = &format
	return nil
}

func (cmb *CredentialManifestBuilder) SetPresentationDefinition(definition exchange.PresentationDefinition) error {
	if cmb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if definition.IsEmpty() {
		return errors.New("cannot set empty presentation definition")
	}

	if err := util.IsValidStruct(definition); err != nil {
		return errors.Wrapf(err, "cannot set invalid presentatino definition: %+v", definition)
	}

	cmb.PresentationDefinition = &definition
	return nil
}

type CredentialApplicationBuilder struct {
	*CredentialApplication
}

func NewCredentialApplicationBuilder(manifestID string) CredentialApplicationBuilder {
	return CredentialApplicationBuilder{
		CredentialApplication: &CredentialApplication{
			ID:          uuid.NewString(),
			SpecVersion: SpecVersion,
			ManifestID:  manifestID,
		},
	}
}

func (cab *CredentialApplicationBuilder) Build() (*CredentialApplication, error) {
	if cab.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := cab.CredentialApplication.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "credential application not ready to be built")
	}

	return cab.CredentialApplication, nil
}

func (cab *CredentialApplicationBuilder) IsEmpty() bool {
	if cab == nil || cab.CredentialApplication.IsEmpty() {
		return true
	}
	return reflect.DeepEqual(cab, &CredentialApplicationBuilder{})
}

func (cab *CredentialApplicationBuilder) SetApplicationManifestID(manifestID string) error {
	if cab.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	cab.ManifestID = manifestID
	return nil
}

func (cab *CredentialApplicationBuilder) SetApplicationClaimFormat(format exchange.ClaimFormat) error {
	if cab.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if len(format.FormatValues()) == 0 {
		return errors.New("cannot set claim format with no values")
	}

	if err := util.IsValidStruct(format); err != nil {
		return errors.Wrapf(err, "cannot set invalid claim format: %+v", format)
	}

	cab.Format = &format
	return nil
}

func (cab *CredentialApplicationBuilder) SetPresentationSubmission(submission exchange.PresentationSubmission) error {
	if cab.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if err := util.IsValidStruct(submission); err != nil {
		return errors.Wrapf(err, "cannot set invalid presentation submission: %+v", submission)
	}

	cab.PresentationSubmission = &submission
	return nil
}

type CredentialResponseBuilder struct {
	*CredentialResponse
}

func NewCredentialResponseBuilder(manifestID string) CredentialResponseBuilder {
	return CredentialResponseBuilder{
		CredentialResponse: &CredentialResponse{
			ID:          uuid.NewString(),
			SpecVersion: SpecVersion,
			ManifestID:  manifestID,
		},
	}
}

func (crb *CredentialResponseBuilder) Build() (*CredentialResponse, error) {
	if crb.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := crb.CredentialResponse.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "credential response not ready to be built")
	}

	return crb.CredentialResponse, nil
}

func (crb *CredentialResponseBuilder) IsEmpty() bool {
	if crb == nil || crb.CredentialResponse.IsEmpty() {
		return true
	}
	return reflect.DeepEqual(crb, &CredentialResponseBuilder{})
}

func (crb *CredentialResponseBuilder) SetManifestID(manifestID string) error {
	if crb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	crb.ManifestID = manifestID
	return nil
}

func (crb *CredentialResponseBuilder) SetApplicationID(applicationID string) error {
	if crb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	crb.ApplicationID = applicationID
	return nil
}

func (crb *CredentialResponseBuilder) SetFulfillment(descriptors []exchange.SubmissionDescriptor) error {
	if crb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if len(descriptors) == 0 {
		return errors.New("cannot set no submission descriptors")
	}

	// validate all descriptors, fail if >= 1 is invalid
	for _, descriptor := range descriptors {
		if err := util.IsValidStruct(descriptor); err != nil {
			return errors.Wrapf(err, "cannot set descriptor map; invalid descriptor: %+v", descriptor)
		}
	}

	crb.Fulfillment = &struct {
		DescriptorMap []exchange.SubmissionDescriptor `json:"descriptor_map" validate:"required"`
	}{
		DescriptorMap: descriptors,
	}
	return nil
}

func (crb *CredentialResponseBuilder) SetDenial(reason string, inputDescriptors []string) error {
	if crb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if len(reason) == 0 {
		return errors.New("cannot set empty reason")
	}

	crb.Denial = &struct {
		Reason           string   `json:"reason" validate:"required"`
		InputDescriptors []string `json:"input_descriptors"`
	}{
		Reason:           reason,
		InputDescriptors: inputDescriptors,
	}
	return nil
}
