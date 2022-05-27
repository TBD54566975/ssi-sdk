package manifest

import (
	"github.com/TBD54566975/ssi-sdk/credential/exchange"
	"github.com/TBD54566975/ssi-sdk/util"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"reflect"
)

const (
	BuilderEmptyError string = "builder cannot be empty"
)

type CredentialManifestBuilder struct {
	*CredentialManifest
}

func NewCredentialManifestBuilder() CredentialManifestBuilder {
	return CredentialManifestBuilder{
		CredentialManifest: &CredentialManifest{
			ID: uuid.NewString(),
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

	if err := util.IsValidStruct(definition); err != nil {
		return errors.Wrapf(err, "cannot set invalid presentatino definition: %+v", definition)
	}

	cmb.PresentationDefinition = &definition
	return nil
}

type CredentialApplicationBuilder struct {
	*CredentialApplication
}

func NewCredentialApplicationBuilder() CredentialApplicationBuilder {
	return CredentialApplicationBuilder{
		CredentialApplication: &CredentialApplication{
			Application: Application{
				ID: uuid.NewString(),
			},
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

	cab.Application.ManifestID = manifestID
	return nil
}

func (cab *CredentialApplicationBuilder) SetApplicationClaimFormat(format exchange.ClaimFormat) error {
	if cab.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	if err := util.IsValidStruct(format); err != nil {
		return errors.Wrapf(err, "cannot set invalid claim format: %+v", format)
	}

	cab.Application.Format = &format
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

type CredentialFulfillmentBuilder struct {
	*CredentialFulfillment
}

func NewCredentialFulfillmentBuilder() CredentialFulfillmentBuilder {
	return CredentialFulfillmentBuilder{
		CredentialFulfillment: &CredentialFulfillment{
			ID: uuid.NewString(),
		},
	}
}

func (cfb *CredentialFulfillmentBuilder) Build() (*CredentialFulfillment, error) {
	if cfb.IsEmpty() {
		return nil, errors.New(BuilderEmptyError)
	}

	if err := cfb.CredentialFulfillment.IsValid(); err != nil {
		return nil, util.LoggingErrorMsg(err, "credential fulfillment not ready to be built")
	}

	return cfb.CredentialFulfillment, nil
}

func (cfb *CredentialFulfillmentBuilder) IsEmpty() bool {
	if cfb == nil || cfb.CredentialFulfillment.IsEmpty() {
		return true
	}
	return reflect.DeepEqual(cfb, &CredentialFulfillmentBuilder{})
}

func (cfb *CredentialFulfillmentBuilder) SetManifestID(manifestID string) error {
	if cfb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	cfb.ManifestID = manifestID
	return nil
}

func (cfb *CredentialFulfillmentBuilder) SetDescriptorMap(descriptors []exchange.SubmissionDescriptor) error {
	if cfb.IsEmpty() {
		return errors.New(BuilderEmptyError)
	}

	// validate all descriptors, fail if >= 1 is invalid
	for _, descriptor := range descriptors {
		if err := util.IsValidStruct(descriptor); err != nil {
			return errors.Wrapf(err, "cannot set descriptor map; invalid descriptor: %+v", descriptor)
		}
	}

	cfb.DescriptorMap = descriptors
	return nil
}